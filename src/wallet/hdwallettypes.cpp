// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/hdwallettypes.h>

int CTransactionRecord::InsertOutput(COutputRecord &r)
{
    for (size_t i = 0; i < vout.size(); ++i) {
        if (vout[i].n == r.n) {
            return 0; // duplicate
        }

        if (vout[i].n < r.n) {
            continue;
        }

        vout.insert(vout.begin() + i, r);
        return 1;
    }
    vout.push_back(r);
    return 1;
};

bool CTransactionRecord::EraseOutput(uint16_t n)
{
    for (size_t i = 0; i < vout.size(); ++i) {
        if (vout[i].n != n) {
            continue;
        }

        vout.erase(vout.begin() + i);
        return true;
    }
    return false;
};

COutputRecord *CTransactionRecord::GetOutput(int n)
{
    // vout is always in order by asc n
    for (auto &r : vout) {
        if (r.n > n) {
            return nullptr;
        }
        if (r.n == n) {
            return &r;
        }
    }
    return nullptr;
};

const COutputRecord *CTransactionRecord::GetOutput(int n) const
{
    // vout is always in order by asc n
    for (const auto &r : vout) {
        if (r.n > n) {
            return nullptr;
        }
        if (r.n == n) {
            return &r;
        }
    }
    return nullptr;
};

const COutputRecord *CTransactionRecord::GetChangeOutput() const
{
    for (const auto &r : vout) {
        if (r.nFlags & ORF_CHANGE) {
            return &r;
        }
    }
    return nullptr;
};

bool CStoredTransaction::InsertBlind(int n, const uint8_t *p)
{
    for (auto &bp : vBlinds) {
        if (bp.first == n) {
            memcpy(bp.second.begin(), p, 32);
            return true;
        }
    }
    uint256 insert;
    memcpy(insert.begin(), p, 32);
    vBlinds.push_back(std::make_pair(n, insert));
    return true;
}

bool CStoredTransaction::GetBlind(int n, uint8_t *p) const
{
    for (const auto &bp : vBlinds) {
        if (bp.first == n) {
            memcpy(p, bp.second.begin(), 32);
            return true;
        }
    }
    return false;
}

bool CStoredTransaction::GetAnonPubkey(int n, CCmpPubKey &anon_pubkey) const
{
    if (!tx || n >= (int)tx->vpout.size()) {
        return false;
    }
    const CTxOutBase *pout = tx->vpout[n].get();
    if (pout->GetType() != OUTPUT_RINGCT) {
        return false;
    }
    anon_pubkey = ((CTxOutRingCT*)pout)->pk;
    return true;
}
