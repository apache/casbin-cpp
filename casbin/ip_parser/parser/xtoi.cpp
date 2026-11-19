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

#ifndef XTOI_CPP
#define XTOI_CPP

#include "casbin/ip_parser/parser/xtoi.h"

namespace casbin {

std::pair<int, int> xtoi(std::string_view s) {
    int n = 0;
    int i = 0;
    std::pair<int, int> p;
    for (i = 0; i < s.length(); i++) {
        if ('0' <= s[i] && s[i] <= '9') {
            n *= 16;
            n += int(s[i] - '0');
        } else if ('a' <= s[i] && s[i] <= 'f') {
            n *= 16;
            n += int(s[i] - 'a') + 10;
        } else if ('A' <= s[i] && s[i] <= 'F') {
            n *= 16;
            n += int(s[i] - 'A') + 10;
        } else {
            break;
        }
        if (n >= big) {
            p.first = 0;
            p.second = i;
            return p;
        }
    }
    if (i == 0) {
        p.first = 0;
        p.second = i;
        return p;
    }
    p.first = n;
    p.second = i;
    return p;
}

} // namespace casbin

#endif // XTOI_CPP
