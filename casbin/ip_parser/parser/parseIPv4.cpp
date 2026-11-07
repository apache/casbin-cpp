/*
 * Copyright (c) 2009 The Go Authors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *    * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Go-derived portions retain the BSD terms above.
 * Casbin-specific contributions are under Apache-2.0; see LICENSE.
 */

#include "casbin/pch.h"

#ifndef PARSEIPV4_CPP
#define PARSEIPV4_CPP

#include "casbin/ip_parser/parser/parseIPv4.h"

namespace casbin {

IP parseIPv4(std::string_view s) {
    std::vector<byte> pb(IP ::IPv4len, 0);
    IP ipv4;
    for (int i = 0; i < IP ::IPv4len; i++) {
        if (s.length() == 0) {
            // Missing octets.
            ipv4.isLegal = false;
            return ipv4;
        }
        if (i > 0) {
            if (s[0] != '.') {
                ipv4.isLegal = false;
                return ipv4;
            }
            s = s.substr(1, s.length() - 1);
        }
        std::pair<int, int> p = dtoi(s);
        if ((p.first >= big || p.second == 0) || p.first > 0xFF) {
            ipv4.isLegal = false;
            return ipv4;
        }
        s = s.substr(p.second, s.length() - p.second);
        pb[i] = p.first;
    }
    if (s.length() != 0) {
        ipv4.isLegal = false;
        return ipv4;
    }
    return IPv4(pb[0], pb[1], pb[2], pb[3]);
}

} // namespace casbin

#endif // PARSEIPV4_CPP
