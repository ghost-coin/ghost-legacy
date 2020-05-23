// Copyright (c) 2017-2018 The Particl Core developers
// Copyright (c) 2020 The Ghost Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_BLIND_H
#define GHOST_BLIND_H

#include <secp256k1.h>
#include <secp256k1_bulletproofs.h>
#include <stdint.h>
#include <vector>

#include <amount.h>

extern secp256k1_context *secp256k1_ctx_blind;
extern secp256k1_scratch_space *blind_scratch;
extern secp256k1_bulletproof_generators *blind_gens;

int SelectRangeProofParameters(uint64_t nValueIn, uint64_t &minValue, int &exponent, int &nBits);

int GetRangeProofInfo(const std::vector<uint8_t> &vRangeproof, int &rexp, int &rmantissa, CAmount &min_value, CAmount &max_value);

void ECC_Start_Blinding();
void ECC_Stop_Blinding();

#endif  // GHOST_BLIND_H
