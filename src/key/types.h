// Copyright (c) 2015 The ShadowCoin developers
// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_KEY_TYPES_H
#define PARTICL_KEY_TYPES_H

typedef std::vector<uint8_t> ec_point;

const size_t EC_SECRET_SIZE = 32;
const size_t EC_COMPRESSED_SIZE = 33;
const size_t EC_UNCOMPRESSED_SIZE = 65;

//typedef struct ec_secret { uint8_t e[EC_SECRET_SIZE]; } ec_secret;

#endif  // PARTICL_KEY_TYPES_H
