// Copyright (c) 2020 barrystyle
// Copyright (c) 2014-2020 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gvr/util.h>

bool GetUTXOCoin(const COutPoint& outpoint, Coin& coin)
{
    LOCK(cs_main);
    if (!::ChainstateActive().CoinsTip().GetCoin(outpoint, coin))
        return false;
    if (coin.IsSpent())
        return false;
    return true;
}

int GetUTXOHeight(const COutPoint& outpoint)
{
    Coin coin;
    return GetUTXOCoin(outpoint, coin) ? coin.nHeight : -1;
}
