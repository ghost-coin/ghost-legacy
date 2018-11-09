// Copyright (c) 2017-2018 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_WALLET_TEST_HDWALLET_TEST_FIXTURE_H
#define PARTICL_WALLET_TEST_HDWALLET_TEST_FIXTURE_H

#include <test/test_bitcoin.h>
#include <interfaces/chain.h>

class CHDWallet;

/** Testing setup and teardown for wallet.
 */
struct HDWalletTestingSetup: public TestingSetup {
    HDWalletTestingSetup(const std::string& chainName = CBaseChainParams::MAIN);
    ~HDWalletTestingSetup();

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain();
    std::unique_ptr<interfaces::Chain::Lock> m_locked_chain = m_chain->assumeLocked();  // Temporary. Removed in upcoming lock cleanup
    std::shared_ptr<CHDWallet> pwalletMain;
};

std::string StripQuotes(std::string s);

#endif // PARTICL_WALLET_TEST_HDWALLET_TEST_FIXTURE_H

