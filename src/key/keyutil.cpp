// Copyright (c) 2017 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key/keyutil.h>

#include <string.h>
#include <crypto/sha256.h>
#include <serialize.h>


static uint32_t BitcoinChecksum(uint8_t *p, uint32_t nBytes)
{
    if (!p || nBytes == 0) {
        return 0;
    }

    uint8_t hash1[32];
    CSHA256().Write(p, nBytes).Finalize((uint8_t*)hash1);
    uint8_t hash2[32];
    CSHA256().Write((uint8_t*)hash1, sizeof(hash1)).Finalize((uint8_t*)hash2);

    // Checksum is the 1st 4 bytes of the hash
    uint32_t checksum;
    memcpy(&checksum, &hash2[0], 4);
    checksum = le32toh(checksum);

    return checksum;
};

bool VerifyChecksum(const std::vector<uint8_t> &data)
{
    if (data.size() < 4) {
        return false;
    }

    uint32_t checksum;
    memcpy(&checksum, &(*(data.end() - 4)), 4);
    checksum = le32toh(checksum);

    return BitcoinChecksum((uint8_t*)&data[0], data.size()-4) == checksum;
};
