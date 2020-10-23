// Copyright (c) 2015-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/url.h>

//#include <event2/http.h>
#include <stdlib.h>
#include <string>
#include <util/strencodings.h>


std::string urlDecode(const std::string &urlEncoded) {
    std::string res;
    if (!urlEncoded.empty()) {
        /* msan...
        char *decoded = evhttp_uridecode(urlEncoded.c_str(), false, nullptr);
        if (decoded) {
            res = std::string(decoded);
            free(decoded);
        }
        */
        size_t in_len = urlEncoded.size();
        res.reserve(in_len);
        for (size_t i = 0; i < in_len; ++i) {
            // evhttp_decode_uri_internal
            char c = urlEncoded[i];
            if ((i + 2) < in_len && c == '%') {
                int d1 = HexDigit(urlEncoded[i+1]);
                int d2 = HexDigit(urlEncoded[i+2]);
                if (d1 > -1 && d2 > -1) {
                    c = (d1 * 16 + d2) & 0xFF;
                    i += 2;
                }
            }
            res += c;
        }
    }
    return res;
}
