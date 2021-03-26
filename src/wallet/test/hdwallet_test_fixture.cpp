// Copyright (c) 2017-2021 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/hdwallet_test_fixture.h>

#include <rpc/server.h>
#include <wallet/db.h>
#include <wallet/hdwallet.h>
#include <wallet/rpcwallet.h>
#include <wallet/coincontrol.h>
#include <validation.h>
#include <util/system.h>
#include <blind.h>
#include <miner.h>
#include <pos/miner.h>
#include <timedata.h>

#include <boost/test/unit_test.hpp>


HDWalletTestingSetup::HDWalletTestingSetup(const std::string &chainName):
    TestingSetup(chainName, true /* fParticlMode */)
{
    ECC_Start_Stealth();
    ECC_Start_Blinding();

    bool fFirstRun;
    pwalletMain = std::make_shared<CHDWallet>(m_chain.get(), WalletLocation(), WalletDatabase::CreateMock());
    AddWallet(pwalletMain);
    pwalletMain->LoadWallet(fFirstRun);
    pwalletMain->handleNotifications();

    m_chain_client->registerRpcs();
}

HDWalletTestingSetup::~HDWalletTestingSetup()
{
    RemoveWallet(pwalletMain);
    pwalletMain.reset();

    mapStakeSeen.clear();
    listStakeSeen.clear();

    ECC_Stop_Stealth();
    ECC_Stop_Blinding();
}

StakeTestingSetup::StakeTestingSetup(const std::string& chainName):
    TestingSetup(chainName, /* fParticlMode */ true, /* with_balance_index */ true)
{
    ECC_Start_Stealth();
    ECC_Start_Blinding();

    bool fFirstRun;
    pwalletMain = std::make_shared<CHDWallet>(m_chain.get(), WalletLocation(), WalletDatabase::CreateMock());
    AddWallet(pwalletMain);
    pwalletMain->LoadWallet(fFirstRun);
    pwalletMain->handleNotifications();

    m_chain_client->registerRpcs();

    SetMockTime(0);
}

StakeTestingSetup::~StakeTestingSetup()
{
    RemoveWallet(pwalletMain);
    pwalletMain.reset();

    mapStakeSeen.clear();
    listStakeSeen.clear();

    ECC_Stop_Stealth();
    ECC_Stop_Blinding();
}

std::string StripQuotes(std::string s)
{
    // Strip double quotes from start and/or end of string
    size_t len = s.length();
    if (len < 2) {
        if (len > 0 && s[0] == '"') {
            s = s.substr(1, len - 1);
        }
        return s;
    }

    if (s[0] == '"') {
        if (s[len-1] == '"') {
            s = s.substr(1, len - 2);
        } else {
            s = s.substr(1, len - 1);
        }
    } else
    if (s[len-1] == '"') {
        s = s.substr(0, len - 2);
    }
    return s;
};

void StakeNBlocks(CHDWallet *pwallet, size_t nBlocks)
{
    size_t nStaked = 0;
    size_t k, nTries = 10000;
    for (k = 0; k < nTries; ++k) {
        int nBestHeight = WITH_LOCK(cs_main, return ::ChainActive().Height());

        int64_t nSearchTime = GetAdjustedTime() & ~Params().GetStakeTimestampMask(nBestHeight+1);
        if (nSearchTime <= pwallet->nLastCoinStakeSearchTime) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }

        CScript coinbaseScript;
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(coinbaseScript, false));
        BOOST_REQUIRE(pblocktemplate.get());

        if (pwallet->SignBlock(pblocktemplate.get(), nBestHeight+1, nSearchTime)) {
            CBlock *pblock = &pblocktemplate->block;

            if (CheckStake(pblock)) {
                nStaked++;
            }
        }

        if (nStaked >= nBlocks) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    BOOST_REQUIRE(k < nTries);
    SyncWithValidationInterfaceQueue();
}

uint256 AddTxn(CHDWallet *pwallet, CTxDestination &dest, OutputTypes input_type, OutputTypes output_type, CAmount amount, CAmount exploit_amount, std::string expect_error)
{
    uint256 txid;
    BOOST_REQUIRE(IsValidDestination(dest));
    {
    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);
    LockAssertion lock(::cs_main);

    std::string sError;
    std::vector<CTempRecipient> vecSend;
    vecSend.emplace_back(output_type, amount, dest);

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    CCoinControl coinControl;
    coinControl.m_debug_exploit_anon = exploit_amount;
    int rv = input_type == OUTPUT_RINGCT ?
        pwallet->AddAnonInputs(*locked_chain, wtx, rtx, vecSend, true, 3, 1, nFee, &coinControl, sError) :
        input_type == OUTPUT_CT ?
        pwallet->AddBlindedInputs(*locked_chain, wtx, rtx, vecSend, true, nFee, &coinControl, sError) :
        pwallet->AddStandardInputs(*locked_chain, wtx, rtx, vecSend, true, nFee, &coinControl, sError);
    BOOST_REQUIRE(rv == 0);

    rv = wtx.SubmitMemoryPoolAndRelay(sError, true, *locked_chain);
    if (expect_error.empty()) {
        BOOST_REQUIRE(rv == 1);
    } else {
        BOOST_CHECK(sError == expect_error);
        BOOST_REQUIRE(rv == 0);
    }

    txid = wtx.GetHash();
    }
    SyncWithValidationInterfaceQueue();

    return txid;
}
