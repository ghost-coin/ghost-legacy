// Copyright (c) 2020 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GVR_UTIL_H
#define GVR_UTIL_H

#include <amount.h>
#include <util/system.h>
#include <validation.h>

bool GetUTXOCoin(const COutPoint& outpoint, Coin& coin);
int GetUTXOHeight(const COutPoint& outpoint);

#endif // GVR_UTIL_H
