
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019 DeVault developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>

class CBlockHeader;
class CBlockIndex;
class uint256;
unsigned int GetNextTargetRequired(const CBlockIndex *pindexLast, const CBlockHeader *pblock);
