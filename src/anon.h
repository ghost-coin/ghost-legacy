// Copyright (c) 2017-2019 The Particl Core developers
// Copyright (c) 2020 The Ghost Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_ANON_H
#define GHOST_ANON_H

#include <sync.h>
#include <pubkey.h>
#include <amount.h>
#include <set>


extern RecursiveMutex cs_main;

class uint256;
class CTxIn;
class CTransaction;
class CTxMemPool;
class TxValidationState;

const size_t MIN_RINGSIZE = 3;
const size_t MAX_RINGSIZE = 32;

const size_t MAX_ANON_INPUTS = 32; // To raise see MLSAG_MAX_ROWS also

const size_t ANON_FEE_MULTIPLIER = 2;

const size_t DEFAULT_RING_SIZE = 5;
const size_t DEFAULT_INPUTS_PER_SIG = 1;


bool VerifyMLSAG(const CTransaction &tx, TxValidationState &state) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

bool AddKeyImagesToMempool(const CTransaction &tx, CTxMemPool &pool);
bool RemoveKeyImagesFromMempool(const uint256 &hash, const CTxIn &txin, CTxMemPool &pool);

bool AllAnonOutputsUnknown(const CTransaction &tx, TxValidationState &state);

bool RollBackRCTIndex(int64_t nLastValidRCTOutput, int64_t nExpectErase, std::set<CCmpPubKey> &setKi);

bool RewindToHeight(int nToHeight, int &nBlocks, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

bool RewindRangeProof(const std::vector<uint8_t> &rangeproof, const std::vector<uint8_t> &commitment, const uint256 &nonce,
                      std::vector<uint8_t> &blind_out, CAmount &value_out);

#endif  // GHOST_ANON_H
