// Copyright (c) 2020 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gvr/payee.h>
#include <gvr/pool.h>
#include <gvr/util.h>

class payee;

bool gvrPaymentsActive(int height)
{
    return height > 25;
}

bool gvrPaymentsEnforced(int height)
{
    return (Params().NetworkIDString() == CBaseChainParams::TESTNET && height > 85);
}

int gvrPaymentRatioSplit(int height)
{
    return 50;
}

void getGVRPayee(payee& currentPayee)
{
    for (auto candidate : verified) {
         currentPayee = candidate;
         break;
    }
}

bool arePayeeEqual(payee& payee1, const CScript& payee2)
{
    bool result = (payee1.GetAddress().ToString() == payee2.ToString());
    return result;
}

bool isGVRPayeeInPool(const CScript& testPayee)
{
    bool found = false;
    int gvrSkewCount = 0;
    int gvrSkewTolerance = 3;
    for (auto candidate : verified) {
         if (++gvrSkewCount > gvrSkewTolerance)
             break;
         if (arePayeeEqual(candidate, testPayee))
             found = true;
    }
    return found;
}
