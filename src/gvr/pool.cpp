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