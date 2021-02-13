// Copyright (c) 2020 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GVR_POOL_H
#define GVR_POOL_H

#include <amount.h>
#include <key_io.h>
#include <util/system.h>
#include <validation.h>

#include <list>
#include <queue>

class payee;

bool gvrPaymentsActive(int height);
bool gvrPaymentsEnforced(int height);
int gvrPaymentRatioSplit(int height);
void getGVRPayee(payee& currentPayee);
bool arePayeeEqual(payee& payee1, const CScript& payee2);
bool isGVRPayeeInPool(const CScript& testPayee);

#endif // GVR_PAYEE_H
