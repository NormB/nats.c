// Copyright 2026 The NATS Authors
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

#include <string.h>
#include <stdlib.h>

#include "srvdns.h"
#include "mem.h"
#include "nuid.h"

#define _SRV_MAX_LABEL_LEN  (63)

static bool
_isHostnameChar(char c)
{
    return (((c >= 'a') && (c <= 'z'))
            || ((c >= 'A') && (c <= 'Z'))
            || ((c >= '0') && (c <= '9'))
            || (c == '-')
            || (c == '_'));
}

bool
natsSRV_isValidHostname(const char *name)
{
    size_t  len;
    size_t  i;
    int     labelLen = 0;

    if (nats_IsStringEmpty(name))
        return false;

    len = strlen(name);
    if (name[len-1] == '.')
        len--;

    if ((len == 0) || (len > NATS_SRV_MAX_NAME_LEN))
        return false;

    for (i=0; i<len; i++)
    {
        if (name[i] == '.')
        {
            if (labelLen == 0)
                return false;
            labelLen = 0;
            continue;
        }
        if (!_isHostnameChar(name[i]) || (++labelLen > _SRV_MAX_LABEL_LEN))
            return false;
    }
    return (labelLen > 0);
}

// Length of `name` without its trailing dot.
static size_t
_nameLen(const char *name)
{
    size_t len = strlen(name);

    if ((len > 0) && (name[len-1] == '.'))
        len--;
    return len;
}

// True if `name` is `d` or a name in `d`.
static bool
_nameInDomain(const char *name, size_t nlen, const char *d, size_t dlen)
{
    if (nlen == dlen)
        return (strncasecmp(name, d, dlen) == 0);
    if (nlen > dlen)
        return ((name[nlen-dlen-1] == '.') && (strncasecmp(name+nlen-dlen, d, dlen) == 0));
    return false;
}

bool
natsSRV_isTargetAllowed(const char *domain, const char *target)
{
    const char  *parent;
    size_t      dlen, tlen;
    size_t      i;
    int         labels = 1;

    if (nats_IsStringEmpty(domain) || nats_IsStringEmpty(target))
        return false;

    dlen = _nameLen(domain);
    tlen = _nameLen(target);
    if ((dlen == 0) || (tlen == 0))
        return false;

    if (_nameInDomain(target, tlen, domain, dlen))
        return true;

    for (i=0; i<dlen; i++)
        if (domain[i] == '.')
            labels++;
    if (labels < 3)
        return false;

    parent = strchr(domain, '.') + 1;
    return _nameInDomain(target, tlen, parent, dlen - (size_t)(parent - domain));
}

natsStatus
natsSRV_parseURL(natsSRVSource **newSrc, bool *isSRV, const char *url)
{
    natsStatus      s       = NATS_OK;
    natsSRVSource   *src    = NULL;
    const char      *ptr    = NULL;
    const char      *sep    = NULL;
    char            *domain = NULL;
    size_t          len;
    bool            tls     = false;

    *newSrc = NULL;
    *isSRV  = false;

    if (url == NULL)
        return NATS_OK;

    if (strncasecmp(url, NATS_SRV_SCHEME, strlen(NATS_SRV_SCHEME)) == 0)
        ptr = url + strlen(NATS_SRV_SCHEME);
    else if (strncasecmp(url, NATS_SRV_TLS_SCHEME, strlen(NATS_SRV_TLS_SCHEME)) == 0)
    {
        ptr = url + strlen(NATS_SRV_TLS_SCHEME);
        tls = true;
    }
    else
        return NATS_OK;

    *isSRV = true;

    src = (natsSRVSource*) NATS_CALLOC(1, sizeof(natsSRVSource));
    if (src == NULL)
        return nats_setDefaultError(NATS_NO_MEMORY);

    src->tls = tls;

    // User info, if any, is everything up to the last '@'. It is kept as is
    // (still percent-encoded) since it ends up in the URLs of the targets.
    sep = strrchr(ptr, '@');
    if (sep != NULL)
    {
        if (sep != ptr)
        {
            src->userInfo = NATS_MALLOC((size_t)(sep - ptr) + 1);
            if (src->userInfo == NULL)
                s = nats_setDefaultError(NATS_NO_MEMORY);
            else
            {
                memcpy(src->userInfo, ptr, (size_t)(sep - ptr));
                src->userInfo[sep - ptr] = '\0';
            }
        }
        ptr = sep + 1;
    }
    if (s == NATS_OK)
    {
        domain = NATS_STRDUP(ptr);
        if (domain == NULL)
            s = nats_setDefaultError(NATS_NO_MEMORY);
    }
    if (s == NATS_OK)
    {
        len = strlen(domain);
        // A single trailing '/' is accepted, then the trailing dot of a
        // fully qualified name.
        if ((len > 0) && (domain[len-1] == '/'))
            domain[--len] = '\0';
        if ((len > 0) && (domain[len-1] == '.'))
            domain[--len] = '\0';

        if (len == 0)
            s = nats_setError(NATS_INVALID_ARG, "%s", "SRV URL has no domain name");
        else if (strchr(domain, '/') != NULL)
            s = nats_setError(NATS_INVALID_ARG, "%s", "SRV URL must not have a path");
        else if ((strchr(domain, ':') != NULL) && (strchr(domain, '[') == NULL))
            s = nats_setError(NATS_INVALID_ARG, "%s",
                              "SRV URL must not have a port, the SRV records provide it");
        else if (!natsSRV_isValidHostname(domain))
            s = nats_setError(NATS_INVALID_ARG, "%s", "SRV URL has an invalid domain name");
    }
    if (s == NATS_OK)
    {
        src->domain = domain;
        *newSrc = src;
    }
    else
    {
        NATS_FREE(domain);
        natsSRV_destroySource(src);
    }
    return NATS_UPDATE_ERR_STACK(s);
}

void
natsSRV_destroySource(natsSRVSource *src)
{
    if (src == NULL)
        return;

    NATS_FREE(src->domain);
    NATS_FREE(src->userInfo);
    NATS_FREE(src);
}

void
natsSRV_destroyRecords(natsSRVRecord *recs, int count)
{
    int i;

    if (recs == NULL)
        return;

    for (i=0; i<count; i++)
        NATS_FREE(recs[i].target);
    NATS_FREE(recs);
}

static int
_cmpDeterministic(const void *a, const void *b)
{
    const natsSRVRecord *ra = (const natsSRVRecord*) a;
    const natsSRVRecord *rb = (const natsSRVRecord*) b;
    int                 c;

    if (ra->priority != rb->priority)
        return (ra->priority < rb->priority ? -1 : 1);
    if (ra->weight != rb->weight)
        return (ra->weight > rb->weight ? -1 : 1);
    c = strcmp(ra->target, rb->target);
    if (c != 0)
        return c;
    if (ra->port != rb->port)
        return (ra->port < rb->port ? -1 : 1);
    return 0;
}

// Lowest priority first, and within a priority, the records with a weight of
// 0 first, as RFC 2782 requires for the weighted selection.
static int
_cmpPriority(const void *a, const void *b)
{
    const natsSRVRecord *ra = (const natsSRVRecord*) a;
    const natsSRVRecord *rb = (const natsSRVRecord*) b;

    if (ra->priority != rb->priority)
        return (ra->priority < rb->priority ? -1 : 1);
    if ((ra->weight == 0) != (rb->weight == 0))
        return (ra->weight == 0 ? -1 : 1);
    return 0;
}

// Moves record `j` to position `i` (i <= j), shifting the records in
// between, so that the remaining ones keep their relative order (records
// with a weight of 0 stay first for the next round).
static void
_moveRecord(natsSRVRecord *recs, int i, int j)
{
    natsSRVRecord tmp;

    if (i == j)
        return;

    tmp = recs[j];
    memmove(&recs[i+1], &recs[i], (size_t)(j - i) * sizeof(natsSRVRecord));
    recs[i] = tmp;
}

// RFC 2782 weighted selection of the records [start, end) which all have
// the same priority.
static void
_selectByWeight(natsSRVRecord *recs, int start, int end)
{
    int     i, j;
    int64_t sum;
    int64_t run;
    int64_t r;

    for (i=start; i<end-1; i++)
    {
        sum = 0;
        for (j=i; j<end; j++)
            sum += recs[j].weight;

        if (sum == 0)
        {
            // Only records with a weight of 0 are left: they are all equally
            // likely to be selected.
            j = i + (int)(nats_Rand64() % (int64_t)(end - i));
        }
        else
        {
            r   = nats_Rand64() % (sum + 1);
            run = 0;
            for (j=i; j<end-1; j++)
            {
                run += recs[j].weight;
                if (run >= r)
                    break;
            }
        }
        _moveRecord(recs, i, j);
    }
}

void
natsSRV_order(natsSRVRecord *recs, int count, bool randomize)
{
    int start, end;

    if ((recs == NULL) || (count <= 1))
        return;

    if (!randomize)
    {
        qsort(recs, (size_t) count, sizeof(natsSRVRecord), _cmpDeterministic);
        return;
    }

    qsort(recs, (size_t) count, sizeof(natsSRVRecord), _cmpPriority);
    for (start=0; start<count; start=end)
    {
        for (end=start+1; (end<count) && (recs[end].priority == recs[start].priority); end++);
        _selectByWeight(recs, start, end);
    }
}

natsStatus
natsSRV_buildURL(char **url, const natsSRVSource *src, const natsSRVRecord *rec)
{
    const char *ui = src->userInfo;

    if (nats_asprintf(url, "%s://%s%s%s:%d",
                      (src->tls ? "tls" : "nats"),
                      (ui != NULL ? ui : ""), (ui != NULL ? "@" : ""),
                      rec->target, rec->port) < 0)
    {
        *url = NULL;
        return nats_setDefaultError(NATS_NO_MEMORY);
    }
    return NATS_OK;
}
