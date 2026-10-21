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

#include "../srvdns.h"

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
