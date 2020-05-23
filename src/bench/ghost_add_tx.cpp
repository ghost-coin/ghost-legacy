// Copyright (c) 2017-2020 The Particl Core developers
// Copyright (c) 2020 The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/hdwallet_test_fixture.h>
#include <bench/bench.h>
#include <wallet/hdwallet.h>
#include <wallet/coincontrol.h>
#include <interfaces/chain.h>

#include <validation.h>
#include <blind.h>
#include <rpc/rpcutil.h>
#include <rpc/blockchain.h>
#include <timedata.h>
#include <miner.h>
#include <pos/miner.h>
#include <util/string.h>
#include <util/translation.h>

CTransactionRef CreateTxn(CHDWallet *pwallet, CBitcoinAddress &address, CAmount amount, int type_in, int type_out, int nRingSize = 5)
{
    LOCK(pwallet->cs_wallet);

    assert(address.IsValid());

    std::vector<CTempRecipient> vecSend;
    std::string sError;
    CTempRecipient r;
    r.nType = type_out;
    r.SetAmount(amount);
    r.address = address.Get();
    vecSend.push_back(r);

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    CCoinControl coinControl;
    if (type_in == OUTPUT_STANDARD) {
        assert(0 == pwallet->AddStandardInputs(wtx, rtx, vecSend, true, nFee, &coinControl, sError));
    } else
    if (type_in == OUTPUT_CT) {
        assert(0 == pwallet->AddBlindedInputs(wtx, rtx, vecSend, true, nFee, &coinControl, sError));
    } else {
        int nInputsPerSig = 1;
        assert(0 == pwallet->AddAnonInputs(wtx, rtx, vecSend, true, nRingSize, nInputsPerSig, nFee, &coinControl, sError));
    }
    return wtx.tx;
}

static void AddAnonTxn(CHDWallet *pwallet, CBitcoinAddress &address, CAmount amount, OutputTypes output_type)
{
    {
    LOCK(pwallet->cs_wallet);

    assert(address.IsValid());

    std::vector<CTempRecipient> vecSend;
    std::string sError;
    CTempRecipient r;
    r.nType = output_type;
    r.SetAmount(amount);
    r.address = address.Get();
    vecSend.push_back(r);

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    CCoinControl coinControl;
    assert(0 == pwallet->AddStandardInputs(wtx, rtx, vecSend, true, nFee, &coinControl, sError));

    assert(wtx.SubmitMemoryPoolAndRelay(sError, true));
    }
    SyncWithValidationInterfaceQueue();
}

void StakeNBlocks(CHDWallet *pwallet, size_t nBlocks)
{
    int nBestHeight;
    size_t nStaked = 0;
    size_t k, nTries = 10000;
    for (k = 0; k < nTries; ++k) {
        nBestHeight = pwallet->chain().getHeightInt();

        int64_t nSearchTime = GetAdjustedTime() & ~Params().GetStakeTimestampMask(nBestHeight+1);
        if (nSearchTime <= pwallet->nLastCoinStakeSearchTime) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }

        CScript coinbaseScript;
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(mempool, Params()).CreateNewBlock(coinbaseScript, false));
        assert(pblocktemplate.get());

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
    assert(k < nTries);
    SyncWithValidationInterfaceQueue();
};

static void AddTx(benchmark::State& state, const std::string from, const std::string to, const bool owned)
{
    TestingSetup test_setup{CBaseChainParams::REGTEST, {}, true};

    ECC_Start_Stealth();
    ECC_Start_Blinding();

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain(*g_rpc_node);
    std::unique_ptr<interfaces::ChainClient> m_chain_client = interfaces::MakeWalletClient(*m_chain, {});
    m_chain_client->registerRpcs();

    uint64_t wallet_creation_flags = WALLET_FLAG_BLANK_WALLET;
    SecureString passphrase;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    WalletLocation location_a("a");
    std::shared_ptr<CHDWallet> pwallet_a = std::static_pointer_cast<CHDWallet>(CWallet::CreateWalletFromFile(*m_chain.get(), location_a, error, warnings, wallet_creation_flags));
    assert(pwallet_a.get());
    pwallet_a->Initialise();
    AddWallet(pwallet_a);

    WalletLocation location_b("b");
    std::shared_ptr<CHDWallet> pwallet_b = std::static_pointer_cast<CHDWallet>(CWallet::CreateWalletFromFile(*m_chain.get(), location_b, error, warnings, wallet_creation_flags));
    assert(pwallet_b.get());
    pwallet_b->Initialise();
    AddWallet(pwallet_b);

    {
        int last_height = ::ChainActive().Height();
        uint256 last_hash = ::ChainActive().Tip()->GetBlockHash();
        {
            LOCK(pwallet_a->cs_wallet);
            pwallet_a->SetLastBlockProcessed(last_height, last_hash);
        }
        {
            LOCK(pwallet_b->cs_wallet);
            pwallet_b->SetLastBlockProcessed(last_height, last_hash);
        }
    }

    std::string from_address_type, to_address_type;
    OutputTypes from_tx_type = OUTPUT_NULL;
    OutputTypes to_tx_type = OUTPUT_NULL;

    UniValue rv;

    CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPeK5mCpvMsd1cwyT1JZsrBN82XkoYuZY1EVK7EwDaiL9sDfqUU5SntTfbRfnRedFWjg5xkDG5i3iwd3yP7neX5F2dtdCojk4", "a");
    CallRPC("extkeyimportmaster \"expect trouble pause odor utility palace ignore arena disorder frog helmet addict\"", "b");

    if (from == "plain") {
        from_address_type = "getnewaddress";
        from_tx_type = OUTPUT_STANDARD;
    } else if (from == "blind") {
        from_address_type = "getnewstealthaddress";
        from_tx_type = OUTPUT_CT;
    } else if (from == "anon") {
        from_address_type = "getnewstealthaddress";
        from_tx_type = OUTPUT_RINGCT;
    }

    if (to == "plain") {
        to_address_type = "getnewaddress";
        to_tx_type = OUTPUT_STANDARD;
    } else if (to == "blind") {
        to_address_type = "getnewstealthaddress";
        to_tx_type = OUTPUT_CT;
    } else if (to == "anon") {
        to_address_type = "getnewstealthaddress";
        to_tx_type = OUTPUT_RINGCT;
    }

    assert(from_tx_type != OUTPUT_NULL);
    assert(to_tx_type != OUTPUT_NULL);

    rv = CallRPC(from_address_type, "a");
    CBitcoinAddress addr_a(part::StripQuotes(rv.write()));

    rv = CallRPC(to_address_type, "b");
    CBitcoinAddress addr_b(part::StripQuotes(rv.write()));

    if (from == "anon" || from == "blind") {
        AddAnonTxn(pwallet_a.get(), addr_a, 1 * COIN, from == "anon" ? OUTPUT_RINGCT : OUTPUT_CT);
        AddAnonTxn(pwallet_a.get(), addr_a, 1 * COIN, from == "anon" ? OUTPUT_RINGCT : OUTPUT_CT);
        AddAnonTxn(pwallet_a.get(), addr_a, 1 * COIN, from == "anon" ? OUTPUT_RINGCT : OUTPUT_CT);
        AddAnonTxn(pwallet_a.get(), addr_a, 1 * COIN, from == "anon" ? OUTPUT_RINGCT : OUTPUT_CT);
        AddAnonTxn(pwallet_a.get(), addr_a, 1 * COIN, from == "anon" ? OUTPUT_RINGCT : OUTPUT_CT);

        StakeNBlocks(pwallet_a.get(), 2);
    }

    CTransactionRef tx = CreateTxn(pwallet_a.get(), owned ? addr_b : addr_a, 1000, from_tx_type, to_tx_type);

    CWalletTx::Confirmation confirm;
    {
    LOCK(pwallet_b.get()->cs_wallet);

    while (state.KeepRunning()) {
        pwallet_b.get()->AddToWalletIfInvolvingMe(tx, confirm, true);
    }
    }

    RemoveWallet(pwallet_a);
    pwallet_a.reset();

    RemoveWallet(pwallet_b);
    pwallet_b.reset();

    ECC_Stop_Stealth();
    ECC_Stop_Blinding();
}

static void GhostAddTxPlainPlainNotOwned(benchmark::State& state) { AddTx(state, "plain", "plain", false); }
static void GhostAddTxPlainPlainOwned(benchmark::State& state) { AddTx(state, "plain", "plain", true); }
static void GhostAddTxPlainBlindNotOwned(benchmark::State& state) { AddTx(state, "plain", "blind", false); }
static void GhostAddTxPlainBlindOwned(benchmark::State& state) { AddTx(state, "plain", "blind", true); }
// static void GhostAddTxPlainAnonNotOwned(benchmark::State& state) { AddTx(state, "plain", "anon", false); }
// static void GhostAddTxPlainAnonOwned(benchmark::State& state) { AddTx(state, "plain", "anon", true); }

static void GhostAddTxBlindPlainNotOwned(benchmark::State& state) { AddTx(state, "blind", "plain", false); }
static void GhostAddTxBlindPlainOwned(benchmark::State& state) { AddTx(state, "blind", "plain", true); }
static void GhostAddTxBlindBlindNotOwned(benchmark::State& state) { AddTx(state, "blind", "blind", false); }
static void GhostAddTxBlindBlindOwned(benchmark::State& state) { AddTx(state, "blind", "blind", true); }
static void GhostAddTxBlindAnonNotOwned(benchmark::State& state) { AddTx(state, "blind", "anon", false); }
static void GhostAddTxBlindAnonOwned(benchmark::State& state) { AddTx(state, "blind", "anon", true); }

static void GhostAddTxAnonPlainNotOwned(benchmark::State& state) { AddTx(state, "anon", "plain", false); }
static void GhostAddTxAnonPlainOwned(benchmark::State& state) { AddTx(state, "anon", "plain", true); }
static void GhostAddTxAnonBlindNotOwned(benchmark::State& state) { AddTx(state, "anon", "blind", false); }
static void GhostAddTxAnonBlindOwned(benchmark::State& state) { AddTx(state, "anon", "blind", true); }
static void GhostAddTxAnonAnonNotOwned(benchmark::State& state) { AddTx(state, "anon", "anon", false); }
static void GhostAddTxAnonAnonOwned(benchmark::State& state) { AddTx(state, "anon", "anon", true); }

BENCHMARK(GhostAddTxPlainPlainNotOwned, 100);
BENCHMARK(GhostAddTxPlainPlainOwned, 100);
BENCHMARK(GhostAddTxPlainBlindNotOwned, 100);
BENCHMARK(GhostAddTxPlainBlindOwned, 100);
// BENCHMARK(GhostAddTxPlainAnonNotOwned, 100);
// BENCHMARK(GhostAddTxPlainAnonOwned, 100);

BENCHMARK(GhostAddTxBlindPlainNotOwned, 100);
BENCHMARK(GhostAddTxBlindPlainOwned, 100);
BENCHMARK(GhostAddTxBlindBlindNotOwned, 100);
BENCHMARK(GhostAddTxBlindBlindOwned, 100);
BENCHMARK(GhostAddTxBlindAnonNotOwned, 100);
BENCHMARK(GhostAddTxBlindAnonOwned, 100);

BENCHMARK(GhostAddTxAnonPlainNotOwned, 100);
BENCHMARK(GhostAddTxAnonPlainOwned, 100);
BENCHMARK(GhostAddTxAnonBlindNotOwned, 100);
BENCHMARK(GhostAddTxAnonBlindOwned, 100);
BENCHMARK(GhostAddTxAnonAnonNotOwned, 100);
BENCHMARK(GhostAddTxAnonAnonOwned, 100);
