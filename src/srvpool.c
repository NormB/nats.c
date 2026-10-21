// Copyright 2015-2020 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "natsp.h"

#include <ctype.h>

#include "mem.h"
#include "url.h"
#include "srvdns.h"

// "host:port", large enough for any host name.
#define _SRV_KEY_LEN    (NATS_SRV_MAX_NAME_LEN + 16)

static void
_freeSrv(natsSrv *srv)
{
    if (srv == NULL)
        return;

    natsUrl_Destroy(srv->url);
    NATS_FREE(srv->tlsName);
    NATS_FREE(srv);
}

static natsStatus
_createSrv(natsSrv **newSrv, char *url, bool implicit, const char *tlsName)
{
    natsStatus  s = NATS_OK;
    natsSrv     *srv = (natsSrv*) NATS_CALLOC(1, sizeof(natsSrv));

    if (srv == NULL)
        return nats_setDefaultError(NATS_NO_MEMORY);

    srv->isImplicit = implicit;

    s = natsUrl_Create(&(srv->url), url);
    if ((s == NATS_OK) && (tlsName != NULL))
    {
        srv->tlsName = NATS_STRDUP(tlsName);
        if (srv->tlsName == NULL)
            s = nats_setDefaultError(NATS_NO_MEMORY);
    }
    if (s == NATS_OK)
        *newSrv = srv;
    else
        _freeSrv(srv);

    return NATS_UPDATE_ERR_STACK(s);
}

// Key of a server in pool->srvExhausted: "host:port", host in lower case.
static void
_srvKey(char *key, size_t keyLen, const char *host, int port)
{
    size_t i;

    snprintf(key, keyLen, "%s:%d", host, port);
    for (i=0; key[i] != '\0'; i++)
        key[i] = (char) tolower((unsigned char) key[i]);
}

// Index of the server for host:port (host compared case-insensitively),
// or -1.
static int
_findSrv(natsSrvPool *pool, const char *host, int port)
{
    int i;

    for (i=0; i<pool->size; i++)
    {
        if ((pool->srvrs[i]->url->port == port)
            && (strcasecmp(pool->srvrs[i]->url->host, host) == 0))
        {
            return i;
        }
    }
    return -1;
}

natsSrv*
natsSrvPool_GetCurrentServer(natsSrvPool *pool, const natsSrv *cur, int *index)
{
    natsSrv *s = NULL;
    int     i;

    for (i = 0; i < pool->size; i++)
    {
        s = pool->srvrs[i];
        if (s == cur)
        {
            if (index != NULL)
                *index = i;

            return s;
        }
    }

    if (index != NULL)
        *index = -1;

    return NULL;
}

// Pop the current server and put onto the end of the list. Select head of list as long
// as number of reconnect attempts under MaxReconnect.
natsSrv*
natsSrvPool_GetNextServer(natsSrvPool *pool, natsOptions *opts, const natsSrv *cur)
{
    natsSrv *s = NULL;
    int     i, j;

    s = natsSrvPool_GetCurrentServer(pool, cur, &i);
    if (i < 0)
        return NULL;

    // Shift left servers past current to the current's position
    for (j = i; j < pool->size - 1; j++)
        pool->srvrs[j] = pool->srvrs[j+1];

    if ((opts->maxReconnect < 0)
        || (s->reconnects < opts->maxReconnect))
    {
        // Move the current server to the back of the list
        pool->srvrs[pool->size - 1] = s;
    }
    else
    {
        // Remove the server from the list. If it was found by an SRV lookup,
        // remember it so that a later lookup does not add it back.
        if (s->fromSRV)
        {
            char key[_SRV_KEY_LEN];

            _srvKey(key, sizeof(key), s->url->host, s->url->port);
            if ((pool->srvExhausted != NULL)
                || (natsStrHash_Create(&(pool->srvExhausted), 4) == NATS_OK))
            {
                if (natsStrHash_Set(pool->srvExhausted, key, true, (void*) 1, NULL) != NATS_OK)
                    nats_clearLastError();
            }
            else
                nats_clearLastError();
        }
        _freeSrv(s);
        pool->size--;
    }

    if (pool->size <= 0)
        return NULL;

    return pool->srvrs[0];
}

void
natsSrvPool_Destroy(natsSrvPool *pool)
{
    natsSrv *srv;
    int     i;

    if (pool == NULL)
        return;

    for (i = 0; i < pool->size; i++)
    {
        srv = pool->srvrs[i];
        _freeSrv(srv);
    }
    natsStrHash_Destroy(pool->urls);
    pool->urls = NULL;

    NATS_FREE(pool->srvrs);
    pool->srvrs = NULL;
    pool->size  = 0;
    NATS_FREE(pool->user);
    NATS_FREE(pool->pwd);
    for (i = 0; i < pool->srvSrcCount; i++)
        natsSRV_destroySource(pool->srvSrcs[i]);
    NATS_FREE(pool->srvSrcs);
    natsStrHash_Destroy(pool->srvExhausted);
    NATS_FREE(pool);
}

static natsStatus
_addURLToPool(natsSrvPool *pool, char *sURL, bool implicit, const char *tlsName)
{
    natsStatus  s;
    natsSrv     *srv = NULL;
    bool        addedToMap = false;
    char        bareURL[_SRV_KEY_LEN];

    s = _createSrv(&srv, sURL, implicit, tlsName);
    if (s != NATS_OK)
        return NATS_UPDATE_ERR_STACK(s);

    // For and explicit URL, we will save the user info if one is provided
    // and if not already done.
    if (!implicit && (pool->user == NULL) && (srv->url->username != NULL))
    {
        DUP_STRING(s, pool->user, srv->url->username);
        if ((s == NATS_OK) && !nats_IsStringEmpty(srv->url->password))
            DUP_STRING(s, pool->pwd, srv->url->password);
        if (s != NATS_OK)
            return NATS_UPDATE_ERR_STACK(s);
    }

    // In the map, we need to add an URL that is just host:port
    snprintf(bareURL, sizeof(bareURL), "%s:%d", srv->url->host, srv->url->port);
    s = natsStrHash_Set(pool->urls, bareURL, true, (void*)1, NULL);
    if (s == NATS_OK)
    {
        addedToMap = true;
        if (pool->size + 1 > pool->cap)
        {
            natsSrv **newArray  = NULL;
            int     newCap      = 2 * pool->cap;

            newArray = (natsSrv**) NATS_REALLOC(pool->srvrs, newCap * sizeof(char*));
            if (newArray == NULL)
                s = nats_setDefaultError(NATS_NO_MEMORY);

            if (s == NATS_OK)
            {
                pool->cap = newCap;
                pool->srvrs = newArray;
            }
        }
        if (s == NATS_OK)
            pool->srvrs[pool->size++] = srv;
    }
    if (s != NATS_OK)
    {
        if (addedToMap)
            natsStrHash_Remove(pool->urls, sURL);

        _freeSrv(srv);
    }

    return NATS_UPDATE_ERR_STACK(s);
}

// Shuffles the servers from `offset`. Servers found by an SRV lookup keep
// their place: their order is the one RFC 2782 prescribes.
static void
_shufflePool(natsSrvPool *pool, int offset)
{
    int     i, j, n;
    natsSrv *tmp;
    int     *slots = NULL;

    if (pool->size <= offset+1)
        return;

    if (!natsSrvPool_HasSRV(pool))
    {
        for (i = offset; i < pool->size; i++)
        {
            j = offset + (int)(nats_Rand64() % (i + 1 - offset));
            tmp = pool->srvrs[i];
            pool->srvrs[i] = pool->srvrs[j];
            pool->srvrs[j] = tmp;
        }
        return;
    }

    slots = (int*) NATS_MALLOC((size_t) pool->size * sizeof(int));
    if (slots == NULL)
        return;

    for (n = 0, i = offset; i < pool->size; i++)
        if (!pool->srvrs[i]->fromSRV)
            slots[n++] = i;

    for (i = 1; i < n; i++)
    {
        j = (int)(nats_Rand64() % (i + 1));
        tmp = pool->srvrs[slots[i]];
        pool->srvrs[slots[i]] = pool->srvrs[slots[j]];
        pool->srvrs[slots[j]] = tmp;
    }
    NATS_FREE(slots);
}

// Adds the server for an SRV record, unless it is already in the pool or
// was removed after MaxReconnect failed attempts.
static natsStatus
_addSRVTarget(natsSrvPool *pool, int srcIdx, const natsSRVRecord *rec, bool *added)
{
    natsStatus  s       = NATS_OK;
    char        *url    = NULL;
    char        key[_SRV_KEY_LEN];
    natsSrv     *srv;

    *added = false;

    _srvKey(key, sizeof(key), rec->target, rec->port);
    if ((pool->srvExhausted != NULL) && (natsStrHash_Get(pool->srvExhausted, key) != NULL))
        return NATS_OK;
    if (_findSrv(pool, rec->target, rec->port) >= 0)
        return NATS_OK;

    s = natsSRV_buildURL(&url, pool->srvSrcs[srcIdx], rec);
    IFOK(s, _addURLToPool(pool, url, false, NULL));
    if (s == NATS_OK)
    {
        srv = pool->srvrs[pool->size - 1];
        srv->fromSRV = true;
        srv->srvSrc  = srcIdx;
        pool->everPopulated = true;
        *added = true;
    }
    NATS_FREE(url);

    return NATS_UPDATE_ERR_STACK(s);
}

static natsStatus
_addSRVSource(natsSrvPool *pool, natsSRVSource *src)
{
    natsSRVSource **srcs;

    srcs = (natsSRVSource**) NATS_REALLOC(pool->srvSrcs,
                                          (size_t)(pool->srvSrcCount + 1) * sizeof(natsSRVSource*));
    if (srcs == NULL)
    {
        natsSRV_destroySource(src);
        return nats_setDefaultError(NATS_NO_MEMORY);
    }
    pool->srvSrcs = srcs;
    pool->srvSrcs[pool->srvSrcCount++] = src;
    return NATS_OK;
}

// Adds a server of the options. For an SRV URL, the targets are looked up
// and added in their RFC 2782 order. A failed lookup is not an error here
// (see natsSrvPool_Create()): its reason is kept in pool->srvErr.
static natsStatus
_addConfiguredURL(natsSrvPool *pool, char *url, int64_t timeout)
{
    natsStatus      s       = NATS_OK;
    natsSRVSource   *src    = NULL;
    natsSRVRecord   *recs   = NULL;
    int             count   = 0;
    int             i;
    bool            isSRV   = false;
    bool            added   = false;

    s = natsSRV_parseURL(&src, &isSRV, url);
    if ((s != NATS_OK) || !isSRV)
        return (s == NATS_OK ? _addURLToPool(pool, url, false, NULL) : NATS_UPDATE_ERR_STACK(s));

    s = _addSRVSource(pool, src);
    if (s != NATS_OK)
        return NATS_UPDATE_ERR_STACK(s);

    if (natsSRV_lookup(&recs, &count, src, timeout) != NATS_OK)
    {
        snprintf(pool->srvErr, sizeof(pool->srvErr), "%s", nats_GetLastError(NULL));
        nats_clearLastError();
        return NATS_OK;
    }
    natsSRV_order(recs, count, pool->randomize);
    for (i=0; (s == NATS_OK) && (i<count); i++)
        s = _addSRVTarget(pool, pool->srvSrcCount - 1, &recs[i], &added);

    natsSRV_destroyRecords(recs, count);

    return NATS_UPDATE_ERR_STACK(s);
}

// Moves the servers [from, pool->size) to the front of the pool.
static void
_moveToFront(natsSrvPool *pool, int from)
{
    int     n = pool->size - from;
    natsSrv **tmp;

    if ((from == 0) || (n <= 0))
        return;

    tmp = (natsSrv**) NATS_MALLOC((size_t) n * sizeof(natsSrv*));
    if (tmp == NULL)
        return;

    memcpy(tmp, &pool->srvrs[from], (size_t) n * sizeof(natsSrv*));
    memmove(&pool->srvrs[n], &pool->srvrs[0], (size_t) from * sizeof(natsSrv*));
    memcpy(&pool->srvrs[0], tmp, (size_t) n * sizeof(natsSrv*));
    NATS_FREE(tmp);
}

natsStatus
natsSrvPool_addNewURLs(natsSrvPool *pool, const natsUrl *curUrl, char **urls, int urlCount, const char *tlsName, bool *added)
{
    natsStatus  s       = NATS_OK;
    char        url[256];
    int         i, j;
    char        *sport;
    int         portPos;
    bool        found;
    bool        isLH;
    natsStrHash *tmp = NULL;
    natsSrv     *srv = NULL;

    // Note about pool randomization: when the pool was first created,
    // it was randomized (if allowed). We keep the order the same (removing
    // implicit servers that are no longer sent to us). New URLs are sent
    // to us in no specific order so don't need extra randomization.

    *added = false;

    // Transform what we got to a map for easy lookups
    s = natsStrHash_Create(&tmp, urlCount);
    if (s != NATS_OK)
        return  NATS_UPDATE_ERR_STACK(s);

    for (i=0; (s == NATS_OK) && (i<urlCount); i++)
    {
        s = natsStrHash_Set(tmp, urls[i], false, (void*)1, NULL);
    }

    // Walk the pool and removed the implicit servers that are no longer in the
    // given array/map
    for (i=0; i<pool->size; i++)
    {
        void *inInfo= NULL;

        srv = pool->srvrs[i];
        snprintf(url, sizeof(url), "%s:%d", srv->url->host, srv->url->port);
        // Check if this URL is in the INFO protocol
        inInfo = natsStrHash_Get(tmp, url);
        // Remove from the temp map so that at the end we are left with only
        // new (or restarted) servers that need to be added to the pool.
        natsStrHash_Remove(tmp, url);
        // Keep servers that were set through Options, but also the one that
        // we are currently connected to (even if it is a discovered server).
        if (!(srv->isImplicit) || (srv->url == curUrl))
        {
            continue;
        }
        if (!inInfo)
        {
            // Remove from server pool. Keep current order.

            // Shift left servers past current to the current's position
            for (j = i; j < pool->size - 1; j++)
            {
                pool->srvrs[j] = pool->srvrs[j+1];
            }
            _freeSrv(srv);
            pool->size--;
            i--;
        }
    }

    // If there are any left in the tmp map, these are new (or restarted) servers
    // and need to be added to the pool.
    if (s == NATS_OK)
    {
        natsStrHashIter iter;
        char            *curl = NULL;

        natsStrHashIter_Init(&iter, tmp);
        while ((s == NATS_OK) && natsStrHashIter_Next(&iter, &curl, NULL))
        {
            // Before adding, check if this is a new (as in never seen) URL.
            // This is used to figure out if we invoke the DiscoveredServersCB

            isLH  = false;
            found = false;

            // Consider localhost:<port>, 127.0.0.1:<port> and [::1]:<port>
            // all the same.
            sport = strrchr(curl, ':');
            portPos = (int) (sport - curl);
            if (((nats_strcasestr(curl, "localhost") == curl) && (portPos == 9))
                    || (strncmp(curl, "127.0.0.1", portPos) == 0)
                    || (strncmp(curl, "[::1]", portPos) == 0))
            {
                isLH = ((curl[0] == 'l') || (curl[0] == 'L'));

                snprintf(url, sizeof(url), "localhost%s", sport);
                found = (natsStrHash_Get(pool->urls, url) != NULL);
                if (!found)
                {
                    snprintf(url, sizeof(url), "127.0.0.1%s", sport);
                    found = (natsStrHash_Get(pool->urls, url) != NULL);
                }
                if (!found)
                {
                    snprintf(url, sizeof(url), "[::1]%s", sport);
                    found = (natsStrHash_Get(pool->urls, url) != NULL);
                }
            }
            else
            {
                found = (natsStrHash_Get(pool->urls, curl) != NULL);
            }

            snprintf(url, sizeof(url), "nats://%s", curl);
            if (!found)
            {
                // Make sure that localhost URL is always stored in lower case.
                if (isLH)
                    snprintf(url, sizeof(url), "nats://localhost%s", sport);

                *added = true;
            }
            s = _addURLToPool(pool, url, true, tlsName);
        }
        natsStrHashIter_Done(&iter);
        if ((s == NATS_OK) && *added && pool->randomize)
            _shufflePool(pool, 1);
    }

    natsStrHash_Destroy(tmp);

    return NATS_UPDATE_ERR_STACK(s);
}

// Create the server pool using the options given.
// We will place a Url option first, followed by any
// Server Options. We will randomize the server pool unlesss
// the NoRandomize flag is set.
natsStatus
natsSrvPool_Create(natsSrvPool **newPool, natsOptions *opts)
{
    natsStatus  s        = NATS_OK;
    natsSrvPool *pool    = NULL;
    int         poolSize;
    int         i;

    poolSize  = (opts->url != NULL ? 1 : 0);
    poolSize += opts->serversCount;

    // If the pool is going to be empty, we will add the default URL.
    if (poolSize == 0)
        poolSize = 1;

    pool = (natsSrvPool*) NATS_CALLOC(1, sizeof(natsSrvPool));
    if (pool == NULL)
        return nats_setDefaultError(NATS_NO_MEMORY);

    pool->srvrs = (natsSrv**) NATS_CALLOC(poolSize, sizeof(natsSrv*));
    if (pool->srvrs == NULL)
    {
        NATS_FREE(pool);
        return nats_setDefaultError(NATS_NO_MEMORY);
    }
    // Set the current capacity. The array of urls may have to grow in
    // the future.
    pool->cap = poolSize;
    pool->randomize = !opts->noRandomize;

    // Map that helps find out if an URL is already known.
    s = natsStrHash_Create(&(pool->urls), poolSize);

    // Add URLs from Options' Servers
    for (i=0; (s == NATS_OK) && (i < opts->serversCount); i++)
        s = _addConfiguredURL(pool, opts->servers[i], opts->timeout);

    if (s == NATS_OK)
    {
        // Randomize if allowed to
        if (pool->randomize)
            _shufflePool(pool, 0);
    }

    // Normally, if this one is set, Options.Servers should not be,
    // but we always allowed that, so continue to do so.
    if ((s == NATS_OK) && (opts->url != NULL))
    {
        int prevSize = pool->size;

        // Add to the end of the array
        s = _addConfiguredURL(pool, opts->url, opts->timeout);
        if ((s == NATS_OK) && (pool->size > 1) && (pool->size > prevSize))
        {
            if (!natsSrvPool_HasSRV(pool))
            {
                // Then swap it with first to guarantee that Options.Url is tried first.
                natsSrv *opstUrl = pool->srvrs[pool->size-1];

                pool->srvrs[pool->size-1] = pool->srvrs[0];
                pool->srvrs[0] = opstUrl;
            }
            else
            {
                // Same, without changing the order of the other servers
                // since SRV targets are ordered.
                _moveToFront(pool, prevSize);
            }
        }
    }
    else if ((s == NATS_OK) && (pool->size == 0) && !natsSrvPool_HasSRV(pool))
    {
        // Place default URL if pool is empty.
        s = _addURLToPool(pool, (char*) NATS_DEFAULT_URL, false, NULL);
    }

    if (s == NATS_OK)
    {
        if (pool->size > 0)
            pool->everPopulated = true;
        // The SRV lookups gave no server. Unless the connection retries
        // (and looks them up again), there is nothing to connect to.
        else if (!opts->retryOnFailedConnect)
            s = nats_setError(NATS_NO_SERVER, "%s", pool->srvErr);
    }

    if (s == NATS_OK)
        *newPool = pool;
    else
        natsSrvPool_Destroy(pool);

    return NATS_UPDATE_ERR_STACK(s);
}

natsStatus
natsSrvPool_GetServers(natsSrvPool *pool, bool implicitOnly, char ***servers, int *count)
{
    natsStatus  s       = NATS_OK;
    char        **srvrs = NULL;
    natsSrv     *srv;
    natsUrl     *url;
    int         i;
    int         discovered = 0;

    if (pool->size == 0)
    {
        *servers = NULL;
        *count   = 0;
        return NATS_OK;
    }

    srvrs = (char **) NATS_CALLOC(pool->size, sizeof(char*));
    if (srvrs == NULL)
        return nats_setDefaultError(NATS_NO_MEMORY);

    for (i=0; ((s == NATS_OK) && (i<pool->size)); i++)
    {
        srv = pool->srvrs[i];
        if (implicitOnly && !srv->isImplicit)
            continue;
        url = srv->url;
        if (nats_asprintf(&(srvrs[discovered]), "nats://%s:%d", url->host, url->port) == -1)
            s = nats_setDefaultError(NATS_NO_MEMORY);
        else
            discovered++;
    }
    if (s == NATS_OK)
    {
        *servers = srvrs;
        *count   = discovered;
    }
    else
    {
        for (i=0; i<discovered; i++)
            NATS_FREE(srvrs[i]);
        NATS_FREE(srvrs);
    }
    return NATS_UPDATE_ERR_STACK(s);
}


natsStatus
natsSrvPool_lookupSRV(natsSrvPool *pool, int64_t timeout, natsSRVResult **newResults)
{
    natsSRVResult   *results = NULL;
    int             i;

    *newResults = NULL;

    if (pool->srvSrcCount == 0)
        return NATS_OK;

    results = (natsSRVResult*) NATS_CALLOC(pool->srvSrcCount, sizeof(natsSRVResult));
    if (results == NULL)
        return nats_setDefaultError(NATS_NO_MEMORY);

    for (i=0; i<pool->srvSrcCount; i++)
    {
        natsSRVResult *r = &results[i];

        r->s = natsSRV_lookup(&(r->recs), &(r->count), pool->srvSrcs[i], timeout);
        if (r->s == NATS_OK)
            natsSRV_order(r->recs, r->count, pool->randomize);
        else
        {
            snprintf(r->err, sizeof(r->err), "%s", nats_GetLastError(NULL));
            nats_clearLastError();
        }
    }
    *newResults = results;

    return NATS_OK;
}

static bool
_srvListed(natsSRVResult *r, natsSrv *srv)
{
    int i;

    for (i=0; i<r->count; i++)
    {
        if ((r->recs[i].port == srv->url->port)
            && (strcasecmp(r->recs[i].target, srv->url->host) == 0))
        {
            return true;
        }
    }
    return false;
}

natsStatus
natsSrvPool_mergeSRV(natsSrvPool *pool, natsSRVResult *results, const natsSrv *cur, bool *changed)
{
    natsStatus  s = NATS_OK;
    natsSrv     *srv;
    bool        added;
    int         k, i;

    *changed = false;

    if (results == NULL)
        return NATS_OK;

    for (k=0; (s == NATS_OK) && (k<pool->srvSrcCount); k++)
    {
        natsSRVResult *r = &results[k];

        if (r->s != NATS_OK)
        {
            snprintf(pool->srvErr, sizeof(pool->srvErr), "%s", r->err);
            continue;
        }

        // Remove the servers of this source that are no longer listed.
        for (i=0; i<pool->size; )
        {
            srv = pool->srvrs[i];
            if (srv->fromSRV && (srv->srvSrc == k) && (srv != cur) && !_srvListed(r, srv))
            {
                memmove(&pool->srvrs[i], &pool->srvrs[i+1],
                        (size_t)(pool->size - i - 1) * sizeof(natsSrv*));
                pool->size--;
                _freeSrv(srv);
                *changed = true;
                continue;
            }
            i++;
        }

        for (i=0; (s == NATS_OK) && (i<r->count); i++)
        {
            s = _addSRVTarget(pool, k, &(r->recs[i]), &added);
            if (added)
                *changed = true;
        }
    }

    return NATS_UPDATE_ERR_STACK(s);
}

void
natsSrvPool_freeSRVResults(natsSrvPool *pool, natsSRVResult *results)
{
    int i;

    if (results == NULL)
        return;

    for (i=0; i<pool->srvSrcCount; i++)
        natsSRV_destroyRecords(results[i].recs, results[i].count);
    NATS_FREE(results);
}
