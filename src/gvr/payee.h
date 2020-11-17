// Copyright (c) 2020 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GVR_PAYEE_H
#define GVR_PAYEE_H

#include <amount.h>
#include <util/system.h>
#include <validation.h>

#include <list>
#include <queue>

class payee {
private:
    COutPoint out;
    CAmount amount;
    int height;

public:
    COutPoint GetOutpoint() const { return out; }
    CAmount GetAmount() const { return amount; }
    int GetHeight() const { return height; }

    payee()
        : out()
        , amount()
        , height()
    {
    }
    payee(COutPoint out, CAmount amount, int height)
        : out(out)
        , amount(amount)
        , height(height)
    {
    }
};

//! configuration
const CAmount MINIMUM_GVR_PAYMENT = 20000 * COIN;

void incomingCandidate(COutPoint out, CAmount amount, int height);
void testCandidate(int height);
void printCandidates();

#endif // GVR_PAYEE_H
