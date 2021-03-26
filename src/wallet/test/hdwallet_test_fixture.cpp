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
    TestingSetup(chainName, { "-balancesindex" }, true /* fParticlMode */)
{
    ECC_Start_Stealth();
    ECC_Start_Blinding();

    bool fFirstRun;
    pwalletMain = std::make_shared<CHDWallet>(m_chain.get(), "", CreateMockWalletDatabase());
    AddWallet(pwalletMain);
    pwalletMain->LoadWallet(fFirstRun);
    m_chain_notifications_handler = m_chain->handleNotifications({ pwalletMain.get(), [](CHDWallet*) {} });
    m_wallet_client->registerRpcs();
}

HDWalletTestingSetup::~HDWalletTestingSetup()
{
    RemoveWallet(pwalletMain, nullopt);
    pwalletMain->Finalise();
    pwalletMain.reset();

    mapStakeSeen.clear();
    listStakeSeen.clear();

    ECC_Stop_Stealth();
    ECC_Stop_Blinding();
}

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

        std::unique_ptr<CBlockTemplate> pblocktemplate = pwallet->CreateNewBlock();
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
    LOCK(pwallet->cs_wallet);

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
        pwallet->AddAnonInputs(wtx, rtx, vecSend, true, 3, 1, nFee, &coinControl, sError) :
        input_type == OUTPUT_CT ?
        pwallet->AddBlindedInputs(wtx, rtx, vecSend, true, nFee, &coinControl, sError) :
        pwallet->AddStandardInputs(wtx, rtx, vecSend, true, nFee, &coinControl, sError);
    BOOST_REQUIRE(rv == 0);

    rv = wtx.SubmitMemoryPoolAndRelay(sError, true);
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
