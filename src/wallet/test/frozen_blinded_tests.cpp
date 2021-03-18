// Copyright (c) 2021 tecnovert
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
    Test spending frozen blinded outputs (rct and ct)
    Can be removed after reintegration period ends.
*/

#include <wallet/hdwallet.h>
#include <wallet/coincontrol.h>
#include <interfaces/chain.h>

#include <wallet/test/hdwallet_test_fixture.h>
#include <chainparams.h>
#include <miner.h>
#include <pos/miner.h>
#include <timedata.h>
#include <coins.h>
#include <net.h>
#include <validation.h>
#include <blind.h>
#include <insight/insight.h>
#include <rpc/rpcutil.h>
#include <rpc/util.h>
#include <util/string.h>
#include <util/translation.h>
#include <util/moneystr.h>

#include <consensus/validation.h>

#include <chrono>
#include <thread>

#include <boost/test/unit_test.hpp>


struct FBTestingSetup: public TestingSetup {
    FBTestingSetup(const std::string& chainName = CBaseChainParams::REGTEST):
        TestingSetup(chainName, true /* fParticlMode */, true /* with_balance_index */)
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

    virtual ~FBTestingSetup()
    {
        RemoveWallet(pwalletMain);
        pwalletMain.reset();

        mapStakeSeen.clear();
        listStakeSeen.clear();

        ECC_Stop_Stealth();
        ECC_Stop_Blinding();
    }

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain();
    std::unique_ptr<interfaces::ChainClient> m_chain_client = interfaces::MakeWalletClient(*m_chain, {});
    std::shared_ptr<CHDWallet> pwalletMain;
};

BOOST_FIXTURE_TEST_SUITE(frozen_blinded_tests, FBTestingSetup)


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

static uint256 AddTxn(CHDWallet *pwallet, CTxDestination &dest, OutputTypes input_type, OutputTypes output_type, CAmount amount, CAmount exploit_amount=0, std::string expect_error="")
{
    uint256 txid;
    BOOST_REQUIRE(IsValidDestination(dest));
    {
    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);
    LockAssertion lock(::cs_main);

    std::vector<CTempRecipient> vecSend;
    std::string sError;
    CTempRecipient r;
    r.nType = output_type;
    r.SetAmount(amount);
    r.address = dest;
    vecSend.push_back(r);

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

std::vector<COutputR> GetAvailable(CHDWallet *pwallet, OutputTypes output_type, bool spend_frozen_blinded=false, bool include_tainted_frozen=false)
{
    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);
    LockAssertion lock(::cs_main);
    CCoinControl cctl;
    cctl.m_spend_frozen_blinded = spend_frozen_blinded;
    cctl.m_include_tainted_frozen = include_tainted_frozen;
    std::vector<COutputR> vAvailableCoins;
    if (output_type == OUTPUT_CT) {
        pwallet->AvailableBlindedCoins(*locked_chain, vAvailableCoins, true, &cctl);
    } else
    if (output_type == OUTPUT_RINGCT) {
        pwallet->AvailableAnonCoins(*locked_chain, vAvailableCoins, true, &cctl);
    } else {
        // unknown type
        BOOST_REQUIRE(false);
    }
    return vAvailableCoins;
}

BOOST_AUTO_TEST_CASE(frozen_blinded_test)
{
    // AppInitParameterInteraction()
    gArgs.SoftSetBoolArg("-acceptanontxn", true);
    gArgs.SoftSetBoolArg("-acceptblindtxn", true);

    SeedInsecureRand();
    CHDWallet *pwallet = pwalletMain.get();
    UniValue rv;

    int peer_blocks = GetNumBlocksOfPeers();
    SetNumBlocksOfPeers(0);

    // Disable rct mint fix
    RegtestParams().GetConsensus_nc().exploit_fix_1_time = 0xffffffff;
    BOOST_REQUIRE(RegtestParams().GenesisBlock().GetHash() == ::ChainActive().Tip()->GetBlockHash());

    // Import the regtest genesis coinbase keys
    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPeK5mCpvMsd1cwyT1JZsrBN82XkoYuZY1EVK7EwDaiL9sDfqUU5SntTfbRfnRedFWjg5xkDG5i3iwd3yP7neX5F2dtdCojk4"));
    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPe3x7bUzkHAJZzCuGqN6y28zFFyg5i7Yqxqm897VCnmMJz6QScsftHDqsyWW5djx6FzrbkF9HSD3ET163z1SzRhfcWxvwL4G"));
    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewextaddress lblHDKey"));

    CTxDestination stealth_address;
    CAmount base_supply = 12500000000000;
    {
        pwallet->SetBroadcastTransactions(true);
        const auto bal = pwallet->GetBalance();
        BOOST_REQUIRE(bal.m_mine_trusted == base_supply);

        BOOST_CHECK_NO_THROW(rv = CallRPC("getnewstealthaddress"));
        stealth_address = DecodeDestination(StripQuotes(rv.write()));
    }
    BOOST_REQUIRE(::ChainActive().Tip()->nMoneySupply == base_supply);

    std::vector<uint256> txids_unexploited;
    for (size_t i = 0; i < 10; ++i) {
        txids_unexploited.push_back(AddTxn(pwallet, stealth_address, OUTPUT_STANDARD, OUTPUT_RINGCT, 20 * COIN));
    }

    // Do exploit
    CHDWalletBalances balances;
    pwallet->GetBalances(balances);
    CAmount plain_balance_before_expolit = balances.nPart + balances.nPartStaked;
    uint256 txid_exploited1 = AddTxn(pwallet, stealth_address, OUTPUT_STANDARD, OUTPUT_RINGCT, 10 * COIN, 3000000 * COIN);
    uint256 txid_exploited2 = AddTxn(pwallet, stealth_address, OUTPUT_STANDARD, OUTPUT_RINGCT, 10 * COIN, 3000000 * COIN);
    uint256 txid_exploited3 = AddTxn(pwallet, stealth_address, OUTPUT_STANDARD, OUTPUT_RINGCT, 10 * COIN, 3000000 * COIN);
    BOOST_CHECK(!txid_exploited1.IsNull());
    BOOST_CHECK(!txid_exploited2.IsNull());
    BOOST_CHECK(!txid_exploited3.IsNull());

    StakeNBlocks(pwallet, 2);

    BOOST_REQUIRE(pwallet->GetAnonBalance() == 18000230 * COIN);
    AddTxn(pwallet, stealth_address, OUTPUT_RINGCT, OUTPUT_STANDARD, 50000 * COIN);
    StakeNBlocks(pwallet, 1);

    pwallet->GetBalances(balances);
    BOOST_REQUIRE(plain_balance_before_expolit + (50000-30) * COIN <= balances.nPart + balances.nPartStaked);

    // Add some blinded txns
    uint256 txid_ct_plain_small = AddTxn(pwallet, stealth_address, OUTPUT_STANDARD, OUTPUT_CT, 11 * COIN);
    uint256 txid_ct_plain_large = AddTxn(pwallet, stealth_address, OUTPUT_STANDARD, OUTPUT_CT, 1100 * COIN);
    uint256 txid_ct_anon_small = AddTxn(pwallet, stealth_address, OUTPUT_RINGCT, OUTPUT_CT, 12 * COIN);
    uint256 txid_ct_anon_large = AddTxn(pwallet, stealth_address, OUTPUT_RINGCT, OUTPUT_CT, 1100 * COIN);

    uint256 txid_anon_large = AddTxn(pwallet, stealth_address, OUTPUT_RINGCT, OUTPUT_RINGCT, 1100 * COIN);
    BOOST_CHECK(!txid_anon_large.IsNull());
    uint32_t nTime = ::ChainActive().Tip()->nTime;

    StakeNBlocks(pwallet, 2);

    BlockBalances blockbalances;
    BOOST_CHECK(blockbalances.plain() == 0);
    BOOST_CHECK(blockbalances.blind() == 0);
    BOOST_CHECK(blockbalances.anon() == 0);
    uint256 tip_hash = ::ChainActive().Tip()->GetBlockHash();
    BOOST_CHECK(GetBlockBalances(tip_hash, blockbalances));
    BOOST_CHECK(blockbalances.plain() == GetUTXOSum());
    BOOST_CHECK(blockbalances.blind() == 1111 * COIN);
    BOOST_CHECK(blockbalances.anon() < -49770 * COIN);

    // Enable fix
    RegtestParams().GetConsensus_nc().exploit_fix_1_time = nTime + 1;
    while (GetTime() < nTime + 1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    BOOST_REQUIRE(gArgs.GetBoolArg("-acceptanontxn", false));

    // Exploit should fail
    AddTxn(pwallet, stealth_address, OUTPUT_STANDARD, OUTPUT_RINGCT, 10 * COIN, 9000000 * COIN, "bad-commitment-sum (code 16)");

    gArgs.ClearForced("-acceptanontxn");
    gArgs.ClearForced("-acceptblindtxn");
    BOOST_REQUIRE(!gArgs.GetBoolArg("-acceptanontxn", false));
    BOOST_REQUIRE(!gArgs.GetBoolArg("-acceptblindtxn", false));

    // CT and RCT should fail
    AddTxn(pwallet, stealth_address, OUTPUT_STANDARD, OUTPUT_RINGCT, 10 * COIN, 9000000 * COIN, "bad-txns-anon-disabled (code 16)");
    AddTxn(pwallet, stealth_address, OUTPUT_STANDARD, OUTPUT_CT, 10 * COIN, 0, "bad-txns-blind-disabled (code 16)");

    BOOST_CHECK_NO_THROW(rv = CallRPC("listunspentanon"));
    BOOST_REQUIRE(rv.size() > 0);
    size_t num_prefork_anon = rv.size();

    BOOST_CHECK_NO_THROW(rv = CallRPC("listunspentblind"));
    BOOST_REQUIRE(rv.size() > 0);
    size_t num_prefork_blind = rv.size();


    // Set frozen blinded markers
    const CBlockIndex *tip = ::ChainActive().Tip();
    RegtestParams().GetConsensus_nc().m_frozen_anon_index = tip->nAnonOutputs;
    RegtestParams().GetConsensus_nc().m_frozen_blinded_height = tip->nHeight;

    BOOST_CHECK_NO_THROW(rv = CallRPC("debugwallet {\"list_frozen_outputs\":true}"));
    size_t num_spendable = rv["num_spendable"].get_int();
    size_t num_unspendable = rv["num_unspendable"].get_int();
    BOOST_CHECK(num_spendable > 0);
    BOOST_CHECK(num_unspendable > 0);
    BOOST_CHECK(AmountFromValue(rv["frozen_outputs"][0]["amount"]) > AmountFromValue(rv["frozen_outputs"][num_spendable + num_unspendable - 1]["amount"]));

    BOOST_CHECK_NO_THROW(rv = CallRPC("debugwallet {\"spend_frozen_output\":true}"));
    BOOST_CHECK(rv["error"].get_str() == "Exploit repair fork is not active yet.");

    // Enable HF2
    RegtestParams().GetConsensus_nc().exploit_fix_2_time = tip->nTime + 1;
    CAmount moneysupply_before_fork = tip->nMoneySupply;

    while (GetTime() < tip->nTime + 1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    // Test spend_frozen_output with num_spendable == 0
    RegtestParams().GetConsensus_nc().m_max_tainted_value_out = 100;
    BOOST_CHECK_NO_THROW(rv = CallRPC("debugwallet {\"list_frozen_outputs\":true}"));
    BOOST_CHECK(rv["num_spendable"].get_int() == 0);
    BOOST_CHECK_NO_THROW(rv = CallRPC("debugwallet {\"spend_frozen_output\":true}"));
    BOOST_CHECK(rv["error"].get_str() == "No spendable outputs.");
    RegtestParams().GetConsensus_nc().m_max_tainted_value_out = 500 * COIN;

    // Build and install ct tainted bloom filter
    CBloomFilter tainted_filter(160, 0.004, 0, BLOOM_UPDATE_NONE);
    tainted_filter.insert(txid_ct_anon_small);
    tainted_filter.insert(txid_ct_anon_large);
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << tainted_filter;

    LoadCTTaintedFilter((const unsigned char*) stream.data(), stream.size());
    BOOST_REQUIRE(IsFrozenBlindOutput(txid_ct_anon_small));
    BOOST_REQUIRE(IsFrozenBlindOutput(txid_ct_anon_large));
    BOOST_REQUIRE(!IsFrozenBlindOutput(txid_ct_plain_small));
    BOOST_REQUIRE(!IsFrozenBlindOutput(txid_ct_plain_large));

    // Test available coins, should be all frozen
    BOOST_CHECK_NO_THROW(rv = CallRPC("listunspentanon"));
    BOOST_REQUIRE(rv.size() == 0);

    BOOST_CHECK_NO_THROW(rv = CallRPC("listunspentblind"));
    BOOST_REQUIRE(rv.size() == 0);


    BOOST_CHECK_NO_THROW(rv = CallRPC("listunspentanon 1 9999999 [] true {\"frozen\":true}"));
    BOOST_REQUIRE(rv.size() < num_prefork_anon);
    BOOST_CHECK_NO_THROW(rv = CallRPC("listunspentanon 1 9999999 [] true {\"frozen\":true,\"include_tainted_frozen\":true}"));
    BOOST_REQUIRE(rv.size() == num_prefork_anon);

    BOOST_CHECK_NO_THROW(rv = CallRPC("listunspentblind 1 9999999 [] true {\"frozen\":true}"));
    BOOST_REQUIRE(rv.size() < num_prefork_blind);
    BOOST_CHECK_NO_THROW(rv = CallRPC("listunspentblind 1 9999999 [] true {\"frozen\":true,\"include_tainted_frozen\":true}"));
    BOOST_REQUIRE(rv.size() == num_prefork_blind);

    CAmount utxo_sum_before_fork = GetUTXOSum();
    BOOST_REQUIRE(utxo_sum_before_fork > moneysupply_before_fork + 48000 * COIN);

    // Test that moneysupply is updated
    CAmount stake_reward = Params().GetProofOfStakeReward(::ChainActive().Tip(), 0);
    StakeNBlocks(pwallet, 1);

    CAmount moneysupply_post_fork = WITH_LOCK(cs_main, return ::ChainActive().Tip()->nMoneySupply);
    pwallet->GetBalances(balances);
    CAmount balance_before = balances.nPart + balances.nPartStaked;
    CAmount utxo_sum_after_fork = GetUTXOSum();
    BOOST_REQUIRE(moneysupply_post_fork == balance_before);
    BOOST_REQUIRE(moneysupply_post_fork == utxo_sum_after_fork);
    BOOST_REQUIRE(utxo_sum_before_fork + stake_reward == utxo_sum_after_fork);

    // Test that the balanceindex is reset
    BOOST_CHECK(GetBlockBalances(::ChainActive().Tip()->GetBlockHash(), blockbalances));
    BOOST_CHECK(blockbalances.plain() == utxo_sum_after_fork);
    BOOST_CHECK(blockbalances.blind() == 0);
    BOOST_CHECK(blockbalances.anon() == 0);

    // Spend a large non tainted ct output
    std::string str_cmd;
    {
        uint256 spend_txid = txid_ct_plain_large;
        int output_n = -1;
        CAmount extract_value = 0;
        {
            std::vector<COutputR> vAvailableCoins = GetAvailable(pwallet, OUTPUT_CT, true);
            for (const auto &c : vAvailableCoins) {
                if (c.txhash == spend_txid) {
                    const COutputRecord *oR = c.rtx->second.GetOutput(c.i);
                    if (oR && oR->nFlags & ORF_OWNED && oR->nValue > 500 * COIN) {
                        output_n = c.i;
                        extract_value = oR->nValue;
                        break;
                    }
                }
            }
        }
        BOOST_REQUIRE(output_n > -1);

        str_cmd = strprintf("sendtypeto blind part [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 5 1 false {\"inputs\":[{\"tx\":\"%s\",\"n\":%d}],\"spend_frozen_blinded\":true,\"show_fee\":true,\"debug\":true}",
                            EncodeDestination(stealth_address), FormatMoney(extract_value), spend_txid.ToString(), output_n);
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        CAmount txFee = rv["fee"].get_int64();
        pwallet->GetBalances(balances);
        BOOST_CHECK(balance_before + extract_value - txFee == balances.nPart + balances.nPartStaked);
        balance_before = balances.nPart + balances.nPartStaked;
    }

    // Try spend a large non tainted ct output
    {
        uint256 spend_txid = txid_ct_anon_large;
        int output_n = -1;
        CAmount extract_value = 0;
        {
            std::vector<COutputR> vAvailableCoins = GetAvailable(pwallet, OUTPUT_CT, true, true);

            for (const auto &c : vAvailableCoins) {
                if (c.txhash == spend_txid) {
                    const COutputRecord *oR = c.rtx->second.GetOutput(c.i);
                    if (oR && oR->nFlags & ORF_OWNED && oR->nValue > 500 * COIN) {
                        output_n = c.i;
                        extract_value = oR->nValue;
                        break;
                    }
                }
            }
        }
        BOOST_REQUIRE(output_n > -1);

        str_cmd = strprintf("sendtypeto blind part [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 5 1 false {\"inputs\":[{\"tx\":\"%s\",\"n\":%d}],\"spend_frozen_blinded\":true,\"test_mempool_accept\":true,\"show_fee\":true,\"debug\":true}",
                            EncodeDestination(stealth_address), FormatMoney(extract_value), spend_txid.ToString(), output_n);
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["mempool-reject-reason"].get_str() == "bad-txns-frozen-blinded-too-large");

        // Update whitelist
        std::vector<uint8_t> vct_whitelist;
        vct_whitelist.resize(32);
        memcpy(vct_whitelist.data(), txid_ct_anon_large.begin(), 32);
        LoadCTWhitelist(vct_whitelist.data(), vct_whitelist.size());

        // Txn should pass now
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["txid"].isStr());
        CAmount txFee = rv["fee"].get_int64();
        pwallet->GetBalances(balances);
        BOOST_CHECK(balance_before + extract_value - txFee == balances.nPart + balances.nPartStaked);
        balance_before = balances.nPart + balances.nPartStaked;
    }

    // Spend a small rct output
    {
        uint256 spend_txid;
        int output_n = -1;
        CAmount extract_value = 0;
        {
            std::vector<COutputR> vAvailableCoins = GetAvailable(pwallet, OUTPUT_RINGCT, true, true);

            for (const auto &c : vAvailableCoins) {
                const COutputRecord *oR = c.rtx->second.GetOutput(c.i);
                if (oR && oR->nFlags & ORF_OWNED && oR->nFlags & ORF_OWNED && oR->nValue < 500 * COIN) {
                    spend_txid = c.txhash;
                    output_n = c.i;
                    extract_value = oR->nValue;
                    break;
                }
            }
        }
        BOOST_REQUIRE(output_n > -1);

        // Check that ringsize > 1 fails, set mixin_selection_mode to avoid failure when setting ranges
        {
            str_cmd = strprintf("sendtypeto anon part [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 2 1 false {\"inputs\":[{\"tx\":\"%s\",\"n\":%d}],\"spend_frozen_blinded\":true,\"test_mempool_accept\":true,\"show_fee\":true,\"mixin_selection_mode\":2,\"use_mixins\":[1,2,3,4]}",
                                EncodeDestination(stealth_address), FormatMoney(extract_value), spend_txid.ToString(), output_n);
            BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
            BOOST_REQUIRE(rv["mempool-reject-reason"].get_str() == "bad-frozen-ringsize");
        }

        str_cmd = strprintf("sendtypeto anon part [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 1 1 false {\"inputs\":[{\"tx\":\"%s\",\"n\":%d}],\"spend_frozen_blinded\":true,\"test_mempool_accept\":true,\"show_fee\":true,\"debug\":true}",
                            EncodeDestination(stealth_address), FormatMoney(extract_value), spend_txid.ToString(), output_n);
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        CAmount txFee = rv["fee"].get_int64();
        pwallet->GetBalances(balances);
        BOOST_CHECK(balance_before + extract_value - txFee == balances.nPart + balances.nPartStaked);

        balance_before = balances.nPart + balances.nPartStaked;
    }

    // Try spend a large rct output
    {
        uint256 spend_txid;
        int output_n = -1;
        CAmount extract_value = 0;
        {
            std::vector<COutputR> vAvailableCoins = GetAvailable(pwallet, OUTPUT_RINGCT, true, true);

            for (const auto &c : vAvailableCoins) {
                const COutputRecord *oR = c.rtx->second.GetOutput(c.i);
                if (oR && oR->nFlags & ORF_OWNED && oR->nValue > 500 * COIN && oR->nValue < 2000 * COIN) {
                    spend_txid = c.txhash;
                    output_n = c.i;
                    extract_value = oR->nValue;
                    break;
                }
            }
        }
        BOOST_REQUIRE(output_n > -1);

        str_cmd = strprintf("sendtypeto anon part [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 1 1 false {\"inputs\":[{\"tx\":\"%s\",\"n\":%d}],\"spend_frozen_blinded\":true,\"test_mempool_accept\":true,\"show_fee\":true,\"debug\":true}",
                            EncodeDestination(stealth_address), FormatMoney(extract_value), spend_txid.ToString(), output_n);
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["mempool-reject-reason"].get_str() == "bad-txns-frozen-blinded-too-large");


        // Whitelist index
        BOOST_CHECK_NO_THROW(rv = CallRPC(strprintf("gettransaction %s true true", spend_txid.ToString())));
        std::string str_ao_pubkey = rv["decoded"]["vout"][output_n]["pubkey"].get_str();
        BOOST_CHECK_NO_THROW(rv = CallRPC(strprintf("anonoutput %s", str_ao_pubkey)));
        int64_t ao_index = rv["index"].get_int64();

        int64_t aoi_whitelist[] = {
            ao_index,
        };
        LoadRCTWhitelist(aoi_whitelist, 1);

        // Transaction should send
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["txid"].isStr());
        CAmount txFee = rv["fee"].get_int64();
        pwallet->GetBalances(balances);
        BOOST_CHECK(balance_before + extract_value - txFee == balances.nPart + balances.nPartStaked);
        balance_before = balances.nPart + balances.nPartStaked;
    }

    StakeNBlocks(pwallet, 1);

    pwallet->GetBalances(balances);
    CAmount moneysupply_before_post_fork_to_blinded = WITH_LOCK(cs_main, return ::ChainActive().Tip()->nMoneySupply);
    BOOST_REQUIRE(moneysupply_before_post_fork_to_blinded == balances.nPart + balances.nPartStaked);
    BOOST_REQUIRE(GetUTXOSum() == moneysupply_before_post_fork_to_blinded);

    BOOST_CHECK(GetBlockBalances(::ChainActive().Tip()->GetBlockHash(), blockbalances));
    BOOST_CHECK(blockbalances.plain() == moneysupply_before_post_fork_to_blinded);
    BOOST_CHECK(blockbalances.blind() == 0);
    BOOST_CHECK(blockbalances.anon() == 0);

    // Send some post-fork blinded txns
    str_cmd = strprintf("sendtypeto part blind [{\"address\":\"%s\",\"amount\":1000}] \"\" \"\" 1 1 false {\"test_mempool_accept\":true,\"show_fee\":true}",
                        EncodeDestination(stealth_address));
    BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
    BOOST_REQUIRE(rv["txid"].isStr());

    for (size_t i = 0; i < 10; ++i) {
        str_cmd = strprintf("sendtypeto part anon [{\"address\":\"%s\",\"amount\":10}] \"\" \"\" 1 1 false {\"test_mempool_accept\":true,\"show_fee\":true}",
                            EncodeDestination(stealth_address));
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["txid"].isStr());
    }
    str_cmd = strprintf("sendtypeto part anon [{\"address\":\"%s\",\"amount\":1000}] \"\" \"\" 1 1 false {\"test_mempool_accept\":true,\"show_fee\":true}",
                        EncodeDestination(stealth_address));
    BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
    BOOST_REQUIRE(rv["txid"].isStr());


    StakeNBlocks(pwallet, 2);


    pwallet->GetBalances(balances);
    CAmount moneysupply_after_post_fork_to_blinded = WITH_LOCK(cs_main, return ::ChainActive().Tip()->nMoneySupply);
    CAmount utxosum = GetUTXOSum();
    BOOST_REQUIRE(utxosum + 2100 * COIN == moneysupply_after_post_fork_to_blinded);
    BOOST_REQUIRE(balances.nPart + balances.nPartStaked + 2100 * COIN == moneysupply_after_post_fork_to_blinded);

    BOOST_CHECK(GetBlockBalances(::ChainActive().Tip()->GetBlockHash(), blockbalances));
    BOOST_CHECK(blockbalances.plain() == utxosum);
    BOOST_CHECK(blockbalances.blind() == 1000 * COIN);
    BOOST_CHECK(blockbalances.anon() == 1100 * COIN);

    // Check that mixing pre and post fork CT fails
    {
        COutPoint op_pre;
        CAmount extract_value_pre = 0;
        {
            std::vector<COutputR> vAvailableCoins = GetAvailable(pwallet, OUTPUT_CT, true, true);

            for (const auto &c : vAvailableCoins) {
                const COutputRecord *oR = c.rtx->second.GetOutput(c.i);
                if (oR && oR->nFlags & ORF_OWNED && oR->nValue < 500 * COIN) {
                    op_pre.hash = c.txhash;
                    op_pre.n = c.i;
                    extract_value_pre = oR->nValue;
                    break;
                }
            }
        }
        BOOST_REQUIRE(op_pre.n < 5000);

        COutPoint op_post;
        CAmount extract_value_post = 0;
        {
            std::vector<COutputR> vAvailableCoins = GetAvailable(pwallet, OUTPUT_CT);

            for (const auto &c : vAvailableCoins) {
                const COutputRecord *oR = c.rtx->second.GetOutput(c.i);
                if (oR && oR->nFlags & ORF_OWNED && oR->nValue < 500 * COIN) {
                    op_post.hash = c.txhash;
                    op_post.n = c.i;
                    extract_value_post = oR->nValue;
                    break;
                }
            }
        }
        BOOST_REQUIRE(op_post.n < 5000);

        CAmount send_value = extract_value_pre + extract_value_post;
        str_cmd = strprintf("sendtypeto blind part [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 1 1 false {\"inputs\":[{\"tx\":\"%s\",\"n\":%d},{\"tx\":\"%s\",\"n\":%d}],\"spend_frozen_blinded\":true,\"test_mempool_accept\":true,\"show_fee\":true}",
                            EncodeDestination(stealth_address), FormatMoney(send_value), op_pre.hash.ToString(), op_pre.n, op_post.hash.ToString(), op_post.n);
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["mempool-reject-reason"].get_str() == "mixed-frozen-blinded");

        // Should fail without spend_frozen_blinded
        str_cmd = strprintf("sendtypeto blind part [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 1 1 false {\"inputs\":[{\"tx\":\"%s\",\"n\":%d},{\"tx\":\"%s\",\"n\":%d}],\"test_mempool_accept\":true,\"show_fee\":true}",
                            EncodeDestination(stealth_address), FormatMoney(send_value), op_pre.hash.ToString(), op_pre.n, op_post.hash.ToString(), op_post.n);
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["mempool-reject-reason"].get_str() == "mixed-frozen-blinded");


        // Should pass without op_pre
        send_value = extract_value_post + 1; // require 2 inputs
        str_cmd = strprintf("sendtypeto blind part [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 1 1 false {\"test_mempool_accept\":true,\"show_fee\":true}",
                            EncodeDestination(stealth_address), FormatMoney(send_value));
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["txid"].isStr());

        // b->b
        send_value = 1 * COIN;
        str_cmd = strprintf("sendtypeto blind blind [{\"address\":\"%s\",\"amount\":%s}] \"\" \"\" 1 1 false {\"test_mempool_accept\":true,\"show_fee\":true}",
                            EncodeDestination(stealth_address), FormatMoney(send_value));
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["txid"].isStr());

        // b->a
        send_value = 1 * COIN;
        str_cmd = strprintf("sendtypeto blind blind [{\"address\":\"%s\",\"amount\":%s}] \"\" \"\" 1 1 false {\"test_mempool_accept\":true,\"show_fee\":true}",
                            EncodeDestination(stealth_address), FormatMoney(send_value));
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["txid"].isStr());
    }

    {
        // Try send with small ringsize
        CAmount send_value = 1 * COIN;
        str_cmd = strprintf("sendtypeto anon anon [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 1 1 false {\"test_mempool_accept\":true,\"show_fee\":true}",
                            EncodeDestination(stealth_address), FormatMoney(send_value));
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["mempool-reject-reason"].get_str() == "bad-anon-ringsize");

        // Otherwise should work
        str_cmd = strprintf("sendtypeto anon part [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 3 1 false {\"test_mempool_accept\":true,\"show_fee\":true}",
                            EncodeDestination(stealth_address), FormatMoney(send_value));
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["txid"].isStr());

        // a->a
        str_cmd = strprintf("sendtypeto anon anon [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 3 1 false {\"test_mempool_accept\":true,\"show_fee\":true}",
                            EncodeDestination(stealth_address), FormatMoney(send_value));
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["txid"].isStr());

        // a->b
        str_cmd = strprintf("sendtypeto anon blind [{\"address\":\"%s\",\"amount\":%s,\"subfee\":true}] \"\" \"\" 3 1 false {\"test_mempool_accept\":true,\"show_fee\":true}",
                            EncodeDestination(stealth_address), FormatMoney(send_value));
        BOOST_CHECK_NO_THROW(rv = CallRPC(str_cmd));
        BOOST_REQUIRE(rv["txid"].isStr());
    }

    StakeNBlocks(pwallet, 2);

    // Check moneysupply didn't climb more than stakes
    stake_reward = Params().GetProofOfStakeReward(::ChainActive().Tip(), 0);
    CAmount moneysupply_after_post_fork_blind_spends = WITH_LOCK(cs_main, return ::ChainActive().Tip()->nMoneySupply);
    BOOST_REQUIRE(moneysupply_after_post_fork_to_blinded + stake_reward * 2 ==  moneysupply_after_post_fork_blind_spends);

    // Test debugwallet spend_frozen_output
    BOOST_CHECK_NO_THROW(rv = CallRPC("debugwallet {\"list_frozen_outputs\":true}"));
    num_spendable = rv["num_spendable"].get_int();
    BOOST_CHECK(num_spendable > 0);

    for (size_t i = 0; i < num_spendable; i++) {
        BOOST_CHECK_NO_THROW(rv = CallRPC("debugwallet {\"spend_frozen_output\":true}"));
        BOOST_REQUIRE(rv["txid"].isStr());
    }

    BOOST_CHECK_NO_THROW(rv = CallRPC("debugwallet {\"list_frozen_outputs\":true}"));
    BOOST_CHECK(rv["num_spendable"].get_int() == 0);
    BOOST_CHECK(rv["num_unspendable"].get_int() > 0);

    // balancesindex tracks the amount of plain coin sent to and from blind to anon.
    // Coins can move between anon and blind but the sums should match
    BOOST_CHECK(GetBlockBalances(::ChainActive().Tip()->GetBlockHash(), blockbalances));

    BOOST_CHECK_NO_THROW(rv = CallRPC("getbalances"));
    CAmount blind_trusted = AmountFromValue(rv["mine"]["blind_trusted"]);
    CAmount anon_trusted = AmountFromValue(rv["mine"]["anon_trusted"]);
    BOOST_CHECK(blind_trusted > blockbalances.blind()); // anon -> blind

    BOOST_CHECK_NO_THROW(rv = CallRPC("debugwallet {\"list_frozen_outputs\":true}"));
    CAmount anon_spendable = anon_trusted - AmountFromValue(rv["total_unspendable"]);
    BOOST_CHECK(anon_spendable < blockbalances.anon()); // anon -> blind
    BOOST_CHECK(anon_spendable + blind_trusted == blockbalances.blind() + blockbalances.anon());

    SetNumBlocksOfPeers(peer_blocks);
}

BOOST_AUTO_TEST_SUITE_END()
