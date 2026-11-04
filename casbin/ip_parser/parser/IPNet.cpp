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

#ifndef IPNET_CPP
#define IPNET_CPP

#include "casbin/ip_parser/parser/IPNet.h"

namespace casbin {

std::string IPNet ::NETIP_toString() {
    std::string ip1, ip2, ip3, ip4;
    std::stringstream ss1, ss2, ss3, ss4;
    ss1 << net_ip.ip[0];
    ss1 >> ip1;
    ss2 << net_ip.ip[1];
    ss2 >> ip2;
    ss3 << net_ip.ip[2];
    ss3 >> ip3;
    ss4 << net_ip.ip[3];
    ss4 >> ip4;
    return ip1 + "." + ip2 + "." + ip3 + "." + ip4;
}

std::string IPNet ::IPMask_toString() {
    std::string mask1, mask2, mask3, mask4;
    std::stringstream ss1, ss2, ss3, ss4;
    ss1 << mask[0];
    ss1 >> mask1;
    ss2 << mask[1];
    ss2 >> mask2;
    ss3 << mask[2];
    ss3 >> mask3;
    ss4 << mask[3];
    ss4 >> mask4;
    return mask1 + "." + mask2 + "." + mask3 + "." + mask4;
}

// Contains reports whether the network includes ip.
bool IPNet ::contains(IP ipNew) {
    std::pair<IP, IPMask> p = networkNumberAndMask(*this);
    IP x;
    x = ipNew.To4();
    if (x.isLegal == true) {
        ipNew = x;
    }
    int l = int(ipNew.ip.size());
    if (l != p.first.ip.size()) {
        return false;
    }
    for (int i = 0; i < l; i++) {
        if ((p.first.ip[i] & p.second[i]) != (ipNew.ip[i] & p.second[i])) {
            return false;
        }
    }
    return true;
}

std::pair<IP, IPMask> IPNet ::networkNumberAndMask(IPNet n) {
    IP newIp;
    newIp = n.net_ip.To4();
    std::pair<IP, IPMask> p;
    p.first = newIp;
    if (newIp.isLegal == false) {
        newIp = n.net_ip;
        if (newIp.ip.size() != IP ::IPv6len) {
            p.first.isLegal = false;
            return p;
        }
    }
    IPMask m = n.mask;
    p.second = m;
    const byte ipv4len = IP ::IPv4len;
    const byte ipv6len = IP ::IPv6len;
    if (m.size() == ipv4len) {
        if (newIp.ip.size() != IP ::IPv4len) {
            p.first.isLegal = false;
        }
    } else if (m.size() == ipv6len) {
        if (newIp.ip.size() == IP ::IPv4len) {
            IPMask newM(m.begin() + 12, m.end());
            m = newM;
            p.first = newIp;
            p.second = m;
        }
    } else {
        p.first.isLegal = false;
    }
    return p;
}

} // namespace casbin

#endif // IPNET_CPP
