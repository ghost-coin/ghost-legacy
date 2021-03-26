// Copyright (c) 2017-2021 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_WALLET_TEST_HDWALLET_TEST_FIXTURE_H
#define PARTICL_WALLET_TEST_HDWALLET_TEST_FIXTURE_H

#include <test/util/setup_common.h>

#include <interfaces/chain.h>
#include <interfaces/wallet.h>

class CHDWallet;

/** Testing setup and teardown for particl wallet.
 */
struct HDWalletTestingSetup: public TestingSetup {
    explicit HDWalletTestingSetup(const std::string& chainName = CBaseChainParams::MAIN);
    virtual ~HDWalletTestingSetup();

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain(m_node);
    std::unique_ptr<interfaces::WalletClient> m_wallet_client = interfaces::MakeWalletClient(*m_chain, *Assert(m_node.args));
    std::shared_ptr<CHDWallet> pwalletMain;
    std::unique_ptr<interfaces::Handler> m_chain_notifications_handler;
};

struct StakeTestingSetup: public HDWalletTestingSetup {
    StakeTestingSetup(const std::string& chainName = CBaseChainParams::REGTEST):
        HDWalletTestingSetup(chainName)
    {
        SetMockTime(0);
    }
};

void StakeNBlocks(CHDWallet *pwallet, size_t nBlocks);
uint256 AddTxn(CHDWallet *pwallet, CTxDestination &dest, OutputTypes input_type, OutputTypes output_type, CAmount amount, CAmount exploit_amount=0, std::string expect_error="");

#endif // PARTICL_WALLET_TEST_HDWALLET_TEST_FIXTURE_H

