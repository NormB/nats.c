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

#include "../natsp.h"

#if defined(NATS_HAS_SRV_LOOKUP)
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#endif

#include "../srvdns.h"
#include "../mem.h"

#if !defined(NATS_HAS_SRV_LOOKUP)

natsStatus
natsSRV_lookup(natsSRVRecord **recs, int *count, const natsSRVSource *src, int64_t timeout)
{
    *recs  = NULL;
    *count = 0;
    return nats_setError(NATS_NOT_PERMITTED, "%s",
                         "SRV lookups are not supported on this platform");
}

void
natsSRV_setTestNameserver(const char *ipv4, int port)
{
}

bool
nats_SupportsSRV(void)
{
    return false;
}

#else

static pthread_mutex_t      _testNSMu   = PTHREAD_MUTEX_INITIALIZER;
static bool                 _testNSSet  = false;
static struct sockaddr_in   _testNS;

void
natsSRV_setTestNameserver(const char *ipv4, int port)
{
    pthread_mutex_lock(&_testNSMu);
    _testNSSet = false;
    if (ipv4 != NULL)
    {
        memset(&_testNS, 0, sizeof(_testNS));
        _testNS.sin_family = AF_INET;
        _testNS.sin_port   = htons((uint16_t) port);
        _testNSSet = (inet_pton(AF_INET, ipv4, &(_testNS.sin_addr)) == 1);
    }
    pthread_mutex_unlock(&_testNSMu);
}

static void
_applyTestNameserver(res_state rs)
{
    pthread_mutex_lock(&_testNSMu);
    if (_testNSSet)
    {
        rs->nsaddr_list[0] = _testNS;
        rs->nscount        = 1;
    }
    pthread_mutex_unlock(&_testNSMu);
}

static natsStatus
_parseAnswer(natsSRVRecord **newRecs, int *newCount, const natsSRVSource *src,
             const char *qname, const unsigned char *answer, int len)
{
    natsStatus          s       = NATS_OK;
    natsSRVRecord       *recs   = NULL;
    int                 count   = 0;
    bool                notAvail= false;
    bool                outside = false;
    ns_msg              msg;
    ns_rr               rr;
    const unsigned char *rd;
    char                target[NS_MAXDNAME];
    int                 n, i, port;
    size_t              tlen;

    if (ns_initparse(answer, len, &msg) < 0)
        return nats_setError(NATS_NO_SERVER, "SRV lookup of '%s' returned a malformed answer", qname);

    n = ns_msg_count(msg, ns_s_an);
    if (n > 0)
    {
        recs = (natsSRVRecord*) NATS_CALLOC((n < NATS_SRV_MAX_RECORDS ? n : NATS_SRV_MAX_RECORDS),
                                            sizeof(natsSRVRecord));
        if (recs == NULL)
            return nats_setDefaultError(NATS_NO_MEMORY);
    }
    for (i=0; (s == NATS_OK) && (i<n) && (count < NATS_SRV_MAX_RECORDS); i++)
    {
        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0)
            break;

        // Answers may contain other records, such as CNAMEs.
        if ((ns_rr_type(rr) != ns_t_srv) || (ns_rr_class(rr) != ns_c_in) || (ns_rr_rdlen(rr) < 7))
            continue;

        rd   = ns_rr_rdata(rr);
        port = (int) ns_get16(rd+4);

        // The target is data from the network: it is only used if it is a
        // valid host name (dn_expand() escapes any special character).
        if (dn_expand(ns_msg_base(msg), ns_msg_end(msg), rd+6, target, sizeof(target)) < 0)
            continue;

        tlen = strlen(target);
        if ((tlen == 0) || ((tlen == 1) && (target[0] == '.')))
        {
            // RFC 2782: "A Target of "." means that the service is decidedly
            // not available at this domain."
            notAvail = true;
            continue;
        }
        if ((port == 0) || !natsSRV_isValidHostname(target))
            continue;
        // DNS answers are not authenticated: do not let them send the
        // connection (and its credentials) anywhere.
        if (!natsSRV_isTargetAllowed(src->domain, target))
        {
            outside = true;
            continue;
        }
        if (target[tlen-1] == '.')
            target[tlen-1] = '\0';

        recs[count].priority = (int) ns_get16(rd);
        recs[count].weight   = (int) ns_get16(rd+2);
        recs[count].port     = port;
        recs[count].target   = NATS_STRDUP(target);
        if (recs[count].target == NULL)
            s = nats_setDefaultError(NATS_NO_MEMORY);
        else
            count++;
    }
    if ((s == NATS_OK) && (count == 0))
    {
        if (notAvail)
            s = nats_setError(NATS_NO_SERVER, "service '%s' is not available (SRV target \".\")", qname);
        else if (outside)
            s = nats_setError(NATS_NO_SERVER, "SRV records of '%s' point outside of '%s'", qname, src->domain);
        else
            s = nats_setError(NATS_NO_SERVER, "SRV lookup of '%s' returned no usable record", qname);
    }
    if (s == NATS_OK)
    {
        *newRecs  = recs;
        *newCount = count;
    }
    else
        natsSRV_destroyRecords(recs, count);

    return NATS_UPDATE_ERR_STACK(s);
}

natsStatus
natsSRV_lookup(natsSRVRecord **recs, int *count, const natsSRVSource *src, int64_t timeout)
{
    natsStatus          s       = NATS_OK;
    unsigned char       *answer = NULL;
    char                qname[sizeof(NATS_SRV_SERVICE) + NATS_SRV_MAX_NAME_LEN + 1];
    struct __res_state  rs;
    int                 len;

    *recs  = NULL;
    *count = 0;

    snprintf(qname, sizeof(qname), "%s%s", NATS_SRV_SERVICE, src->domain);

    // A resolver state per lookup: res_nquery() is then safe to use from
    // any thread.
    memset(&rs, 0, sizeof(rs));
    if (res_ninit(&rs) != 0)
        return nats_setError(NATS_SYS_ERROR, "SRV lookup of '%s': unable to initialize the resolver", qname);

    // One attempt per nameserver, bounded by the connect timeout.
    rs.retrans = (int)((timeout + 999) / 1000);
    if (rs.retrans < 1)
        rs.retrans = 1;
    rs.retry = 1;

    _applyTestNameserver(&rs);

    answer = (unsigned char*) NATS_MALLOC(NS_MAXMSG);
    if (answer == NULL)
        s = nats_setDefaultError(NATS_NO_MEMORY);

    if (s == NATS_OK)
    {
        len = res_nquery(&rs, qname, ns_c_in, ns_t_srv, answer, NS_MAXMSG);
        if (len < 0)
            s = nats_setError(NATS_NO_SERVER, "SRV lookup of '%s' failed: %s",
                              qname, hstrerror(rs.res_h_errno));
        else
            s = _parseAnswer(recs, count, src, qname, answer, (len > NS_MAXMSG ? NS_MAXMSG : len));
    }

    NATS_FREE(answer);
#if defined(__APPLE__)
    res_ndestroy(&rs);
#else
    res_nclose(&rs);
#endif

    return NATS_UPDATE_ERR_STACK(s);
}

bool
nats_SupportsSRV(void)
{
    return true;
}

#endif
