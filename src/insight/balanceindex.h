// Copyright (c) 2021 tecnovert
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_INSIGHT_BALANCEINDEX_H
#define PARTICL_INSIGHT_BALANCEINDEX_H

enum BalanceIndexType {
    BAL_IND_PLAIN_ADDED                 = 0,
    BAL_IND_PLAIN_REMOVED               = 1,
    BAL_IND_BLIND_ADDED                 = 2,
    BAL_IND_BLIND_REMOVED               = 3,
    BAL_IND_ANON_ADDED                  = 4,
    BAL_IND_ANON_REMOVED                = 5,
};

enum BlockBalanceIndexType {
    BAL_IND_PLAIN                       = 0,
    BAL_IND_BLIND                       = 1,
    BAL_IND_ANON                        = 2,
};

class BlockBalances
{
public:
    BlockBalances() {};
    BlockBalances(CAmount balances[3]) { for (size_t i = 0; i < 3; ++i) m_balances[i] = balances[i]; };
    void sum(const BlockBalances &prev) { for (size_t i = 0; i < 3; ++i) m_balances[i] += prev.m_balances[i]; };

    CAmount plain() { return m_balances[BAL_IND_PLAIN]; };
    CAmount blind() { return m_balances[BAL_IND_BLIND]; };
    CAmount anon()  { return m_balances[BAL_IND_ANON];  };

    CAmount m_balances[3] = {0};
    SERIALIZE_METHODS(BlockBalances, obj)
    {
        for (size_t i = 0; i < 3; ++i) {
            READWRITE(obj.m_balances[i]);
        }
    }
};

#endif // PARTICL_INSIGHT_BALANCEINDEX_H
