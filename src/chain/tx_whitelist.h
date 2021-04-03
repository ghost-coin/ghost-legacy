// Copyright (c) 2021 tecnovert
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_CHAIN_TX_WHITELIST_H
#define PARTICL_CHAIN_TX_WHITELIST_H

// error: zero size arrays are an extension
// fill with one dummy element

unsigned char tx_whitelist_data[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
unsigned int tx_whitelist_data_len = 32;

int64_t anon_index_whitelist[] = {
    0,
};
size_t anon_index_whitelist_size = sizeof(anon_index_whitelist) / sizeof(int64_t);

#endif // PARTICL_CHAIN_TX_WHITELIST_H
