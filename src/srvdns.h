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

#ifndef SRVDNS_H_
#define SRVDNS_H_

#include <stdbool.h>
#include <stdint.h>

#include "status.h"

// DNS SRV based server discovery.
//
// A server URL of the form "nats+srv://[user[:pass]@]domain" (or "tls+srv://")
// is not dialed directly: the SRV records of "_nats._tcp.<domain>" are looked
// up and each target becomes a "nats://" (or "tls://") server of the pool,
// ordered as RFC 2782 prescribes.

#define NATS_SRV_SCHEME         "nats+srv://"
#define NATS_SRV_TLS_SCHEME     "tls+srv://"
#define NATS_SRV_SERVICE        "_nats._tcp."

// Maximum number of SRV records used from a single answer.
#define NATS_SRV_MAX_RECORDS    (64)

// Maximum length of a domain name (without the trailing dot).
#define NATS_SRV_MAX_NAME_LEN   (253)

typedef struct __natsSRVSource
{
    char    *domain;    // validated, without trailing dot
    char    *userInfo;  // "user[:pass]" as found in the URL, or NULL
    bool    tls;        // "tls+srv://"

} natsSRVSource;

typedef struct __natsSRVRecord
{
    int     priority;
    int     weight;
    int     port;
    char    *target;

} natsSRVRecord;

// Returns true if `name` is a valid host name: dot separated labels of 1 to 63
// characters out of [A-Za-z0-9-_], at most NATS_SRV_MAX_NAME_LEN characters
// in total, with an optional trailing dot.
bool
natsSRV_isValidHostname(const char *name);

// Returns true if an SRV record of `domain` may point to `target`: the
// target must be the domain itself or a name in it. If the domain has
// three labels or more, names in its parent domain are accepted too (the
// SRV records of "nats.example.com" may point to "n1.example.com").
// Comparisons are case-insensitive and ignore a trailing dot.
bool
natsSRV_isTargetAllowed(const char *domain, const char *target);

// Sets `*isSRV` to true and creates `*src` if `url` uses one of the SRV
// schemes. For any other URL, `*isSRV` is false and `*src` is left NULL.
natsStatus
natsSRV_parseURL(natsSRVSource **src, bool *isSRV, const char *url);

void
natsSRV_destroySource(natsSRVSource *src);

// Looks up the SRV records of "_nats._tcp.<src->domain>", waiting at most
// about `timeout` milliseconds (at least one second) per nameserver.
// Records with an invalid target, a target outside of the domain (see
// natsSRV_isTargetAllowed) or a port of 0 are skipped. Fails with
// NATS_NO_SERVER if no usable record is found. Platform specific (see
// unix/srvlookup.c and win/srvlookup.c).
natsStatus
natsSRV_lookup(natsSRVRecord **recs, int *count, const natsSRVSource *src, int64_t timeout);

void
natsSRV_destroyRecords(natsSRVRecord *recs, int count);

// Orders the records as RFC 2782 prescribes: lowest priority first and,
// within a priority, a weighted random selection. If `randomize` is false,
// records of the same priority are ordered by decreasing weight, then by
// target and port, so that the result is deterministic.
void
natsSRV_order(natsSRVRecord *recs, int count, bool randomize);

// Creates the server URL ("nats://" or "tls://", with the source's user
// info if any) for the given record.
natsStatus
natsSRV_buildURL(char **url, const natsSRVSource *src, const natsSRVRecord *rec);

// For tests only: send queries to this IPv4 nameserver, listed `count`
// times (1 to MAXNS), as if the system had that many nameservers (NULL to
// restore the system configuration).
void
natsSRV_setTestNameserver(const char *ipv4, int port, int count);

#endif /* SRVDNS_H_ */
