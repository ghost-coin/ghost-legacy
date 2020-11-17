// Copyright (c) 2020 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gvr/payee.h>
#include <gvr/util.h>

class payee;

std::queue<payee> candidates;
std::list<payee> verified;

//! called whilst iterating txes in block
void incomingCandidate(COutPoint out, CAmount amount, int height)
{
    if (!height)
        return;
    if (amount < MINIMUM_GVR_PAYMENT)
        return;
    payee candidate(out, amount, height);
    candidates.push(candidate);
}

//! called after last tx in block
void testCandidate(int height)
{
    if (!height)
        return;

    //! see if candidate is already in list
    for (int i = 0; i < candidates.size(); i++) {
        bool found = false;
        payee candidate = candidates.front();
        for (auto& storedpayee : verified) {
            if (storedpayee.GetOutpoint() == candidate.GetOutpoint()) {
                found = true;
            }
        }
        if (!found)
            verified.push_back(candidate);
        candidates.pop();
    }

    //! check if any verified members spent their outpoint
    int n = 0;
    std::list<payee>::iterator it = verified.begin();
    while (it != verified.end()) {
        auto payeeout = it->GetOutpoint();
        int spendheight = GetUTXOHeight(payeeout);
        if (spendheight == -1) {
            it = verified.erase(it);
        } else {
            ++it;
        }
        n++;
    }
}

//! print the current payee list
void printCandidates()
{
    //! print modified list
    int n = 0;
    for (auto candidate : verified) {
        LogPrintf("  %02d -  %s (amount: %lld, height: %d)\n",
                  n++, candidate.GetOutpoint().ToString().c_str(), candidate.GetAmount() / COIN, candidate.GetHeight());
    }
}
