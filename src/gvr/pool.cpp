// Copyright (c) 2020 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gvr/payee.h>
#include <gvr/pool.h>
#include <gvr/util.h>

class payee;

bool gvrPaymentsActive(int height)
{
    return false;
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

static bool arePayeeEqual(payee& payee1, payee& payee2)
{
    bool result = (payee1.GetOutpoint() == payee2.GetOutpoint() &&
                   payee1.GetAmount() == payee2.GetAmount() &&
                   payee1.GetHeight() == payee2.GetHeight());
    return result;
}

bool isGVRPayeeInPool(payee& testPayee)
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
