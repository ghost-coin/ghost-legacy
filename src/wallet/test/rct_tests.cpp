// Copyright (c) 2021 tecnovert
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


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
#include <anon.h>
#include <blind.h>
#include <rpc/rpcutil.h>
#include <rpc/util.h>
#include <util/string.h>
#include <util/translation.h>
#include <util/moneystr.h>

#include <consensus/validation.h>
#include <consensus/tx_verify.h>

#include <secp256k1_mlsag.h>

#include <chrono>
#include <thread>

#include <boost/test/unit_test.hpp>


BOOST_FIXTURE_TEST_SUITE(rct_tests, StakeTestingSetup)


bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, BlockValidationState &state)
{
    // Copy of ChainstateManager::ProcessNewBlock with state passthrough
    CBlockIndex *pindex = nullptr;
    bool fForceProcessing = true;
    {
        LOCK(cs_main);
        bool ret = CheckBlock(*pblock, state, chainparams.GetConsensus());
        if (ret) {
            ret = ::ChainstateActive().AcceptBlock(pblock, state, chainparams, &pindex, fForceProcessing, nullptr, nullptr);
        }
        if (!ret) {
            return error("%s: AcceptBlock FAILED (%s)", __func__, state.ToString());
        }
    }
    state.m_preserve_state = true; // else would be cleared
    if (!::ChainstateActive().ActivateBestChain(state, chainparams, pblock) || !state.IsValid()) {
        return error("%s: ActivateBestChain failed (%s)", __func__, state.ToString());
    }
    return true;
}


BOOST_AUTO_TEST_CASE(rct_test)
{
    SeedInsecureRand();
    CHDWallet *pwallet = pwalletMain.get();
    util::Ref context{m_node};
    {
        int last_height = WITH_LOCK(cs_main, return ::ChainActive().Height());
        uint256 last_hash = WITH_LOCK(cs_main, return ::ChainActive().Tip()->GetBlockHash());
        WITH_LOCK(pwallet->cs_wallet, pwallet->SetLastBlockProcessed(last_height, last_hash));
    }
    UniValue rv;
    std::string sError;

    int peer_blocks = GetNumBlocksOfPeers();
    SetNumBlocksOfPeers(0);

    // Import the regtest genesis coinbase keys
    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPeK5mCpvMsd1cwyT1JZsrBN82XkoYuZY1EVK7EwDaiL9sDfqUU5SntTfbRfnRedFWjg5xkDG5i3iwd3yP7neX5F2dtdCojk4", context));
    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPe3x7bUzkHAJZzCuGqN6y28zFFyg5i7Yqxqm897VCnmMJz6QScsftHDqsyWW5djx6FzrbkF9HSD3ET163z1SzRhfcWxvwL4G", context));
    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewextaddress lblHDKey", context));

    CTxDestination stealth_address;
    CAmount base_supply = 12500000000000;
    {
        LOCK(pwallet->cs_wallet);
        pwallet->SetBroadcastTransactions(true);
        const auto bal = pwallet->GetBalance();
        BOOST_REQUIRE(bal.m_mine_trusted == base_supply);

        BOOST_CHECK_NO_THROW(rv = CallRPC("getnewstealthaddress", context));
        stealth_address = DecodeDestination(part::StripQuotes(rv.write()));
    }
    BOOST_REQUIRE(::ChainActive().Tip()->nMoneySupply == base_supply);

    std::vector<uint256> txids_unexploited;
    for (size_t i = 0; i < 10; ++i) {
        txids_unexploited.push_back(AddTxn(pwallet, stealth_address, OUTPUT_STANDARD, OUTPUT_RINGCT, 20 * COIN));
    }

    StakeNBlocks(pwallet, 2);

    // Verify duplicate input fails
    {
    LOCK(pwallet->cs_wallet);
    CPubKey pk_to;
    BOOST_REQUIRE(0 == pwallet->NewKeyFromAccount(pk_to));

    std::vector<CTempRecipient> vecSend;
    CTxDestination dest = PKHash(pk_to);
    vecSend.emplace_back(OUTPUT_STANDARD, 1 * COIN, dest);

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    CCoinControl cctl;
    BOOST_REQUIRE(0 == pwallet->AddAnonInputs(wtx, rtx, vecSend, true, 3, 1, nFee, &cctl, sError));

    // Validate
    {
    LOCK(cs_main);
    int nSpendHeight = ::ChainActive().Tip()->nHeight;
    TxValidationState state;
    state.m_exploit_fix_1 = true;
    state.m_exploit_fix_2 = true;
    state.m_spend_height = nSpendHeight;
    CAmount txfee = 0;
    CCoinsViewCache &view = ::ChainstateActive().CoinsTip();
    BOOST_REQUIRE(Consensus::CheckTxInputs(*wtx.tx, state, view, nSpendHeight, txfee));
    BOOST_REQUIRE(VerifyMLSAG(*wtx.tx, state));

    // Rewrite input matrix to add duplicate index
    CMutableTransaction mtx(*wtx.tx);
    CTxIn &txin = mtx.vin[0];

    std::vector<uint8_t> &vMI = txin.scriptWitness.stack[0];
    std::vector<int64_t> indices;
    indices.reserve(vMI.size());

    uint32_t nSigInputs, nSigRingSize;
    txin.GetAnonInfo(nSigInputs, nSigRingSize);
    size_t ofs = 0, nb = 0;
    for (size_t k = 0; k < nSigInputs; ++k) {
        for (size_t i = 0; i < nSigRingSize; ++i) {
            int64_t anon_index;
            BOOST_REQUIRE(0 == part::GetVarInt(vMI, ofs, (uint64_t&)anon_index, nb));
            ofs += nb;
            indices.push_back(anon_index);
        }
    }
    vMI.clear();
    for (size_t i = 0; i < indices.size(); ++i) {
        size_t use_i = i == 1 ? 0 : i; // Make duplicate
        BOOST_REQUIRE(0 == part::PutVarInt(vMI, indices[use_i]));
    }

    // Should fail verification
    CTransaction fail_tx(mtx);
    BOOST_REQUIRE(Consensus::CheckTxInputs(fail_tx, state, view, nSpendHeight, txfee));
    BOOST_REQUIRE(!VerifyMLSAG(fail_tx, state));
    BOOST_REQUIRE(state.GetRejectReason() == "bad-anonin-dup-i");
    }
    }


    // Verify duplicate keyimage fails
    {
    LOCK(pwallet->cs_wallet);
    CPubKey pk_to;
    BOOST_REQUIRE(0 == pwallet->NewKeyFromAccount(pk_to));

    // Pick inputs so two are used
    CCoinControl cctl;
    std::vector<COutputR> vAvailableCoins;
    pwallet->AvailableAnonCoins(vAvailableCoins, true, &cctl, 100000);
    BOOST_REQUIRE(vAvailableCoins.size() > 2);
    CAmount prevouts_sum = 0;
    for (const auto &output : vAvailableCoins) {
        const COutputRecord *pout = output.rtx->second.GetOutput(output.i);
        prevouts_sum += pout->nValue;
        cctl.Select(COutPoint(output.txhash, output.i));
        if (cctl.NumSelected() >= 2) {
            break;
        }
    }

    std::vector<CTempRecipient> vecSend;
    CTxDestination dest = PKHash(pk_to);
    vecSend.emplace_back(OUTPUT_STANDARD, prevouts_sum, dest);
    vecSend.back().fSubtractFeeFromAmount = true;

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    BOOST_REQUIRE(0 == pwallet->AddAnonInputs(wtx, rtx, vecSend, true, 3, 1, nFee, &cctl, sError));
    BOOST_REQUIRE(wtx.tx->vin.size() == 2);

    // Validate
    {
    LOCK(cs_main);
    int nSpendHeight = ::ChainActive().Tip()->nHeight;
    TxValidationState state;
    state.m_exploit_fix_1 = true;
    state.m_exploit_fix_2 = true;
    state.m_spend_height = nSpendHeight;
    CAmount txfee = 0;
    CCoinsViewCache &view = ::ChainstateActive().CoinsTip();
    BOOST_REQUIRE(Consensus::CheckTxInputs(*wtx.tx, state, view, nSpendHeight, txfee));
    BOOST_REQUIRE(VerifyMLSAG(*wtx.tx, state));

    // Rewrite scriptData to add duplicate keyimage
    CMutableTransaction mtx(*wtx.tx);
    std::vector<uint8_t> &vKeyImages0 = mtx.vin[0].scriptData.stack[0];
    std::vector<uint8_t> &vKeyImages1 = mtx.vin[1].scriptData.stack[0];
    memcpy(vKeyImages1.data(), vKeyImages0.data(), 33);

    // Changing the keyimage changes the txid, resign the first sig
    auto &txin = mtx.vin[0];
    uint256 blinding_factor_prevout;
    uint8_t rand_seed[32];
    GetStrongRandBytes(rand_seed, 32);

    uint32_t nInputs, nRingSize;
    txin.GetAnonInfo(nInputs, nRingSize);
    size_t nCols = nRingSize;
    size_t nRows = nInputs + 1;

    std::vector<uint8_t> &vKeyImages = txin.scriptData.stack[0];
    std::vector<uint8_t> &vMI = txin.scriptWitness.stack[0];
    std::vector<uint8_t> &vDL = txin.scriptWitness.stack[1];
    std::vector<const uint8_t*> vpsk(nRows), vpBlinds;

    std::vector<secp256k1_pedersen_commitment> vCommitments;
    vCommitments.reserve(nCols * nInputs);
    std::vector<const uint8_t*> vpOutCommits;
    std::vector<const uint8_t*> vpInCommits(nCols * nInputs);
    std::vector<uint8_t> vM(nCols * nRows * 33);

    CKey key;
    size_t real_column = 5000;
    size_t ofs = 0, nB = 0;
    for (size_t k = 0; k < nInputs; ++k)
    for (size_t i = 0; i < nCols; ++i) {
        int64_t nIndex;
        BOOST_REQUIRE(0 == part::GetVarInt(vMI, ofs, (uint64_t&)nIndex, nB));
        ofs += nB;

        CAnonOutput ao;
        BOOST_REQUIRE(pblocktree->ReadRCTOutput(nIndex, ao));
        memcpy(&vM[(i+k*nCols)*33], ao.pubkey.begin(), 33);
        vCommitments.push_back(ao.commitment);
        vpInCommits[i+k*nCols] = vCommitments.back().data;

        // Find real input
        if (real_column < 5000) {
            continue; // skip if found, so as not to overwrite key
        }
        CKeyID idk = ao.pubkey.GetID();
        if (pwallet->GetKey(idk, key)) {
            CCmpPubKey test_keyimage;
            BOOST_REQUIRE(0 == GetKeyImage(test_keyimage, ao.pubkey, key));
            const CCmpPubKey &ki = *((CCmpPubKey*)&vKeyImages[k*33]);
            if (test_keyimage == ki) {
                real_column = i;
                vpsk[0] = key.begin();

                // Get blinding factor
                CHDWalletDB wdb(pwallet->GetDatabase());
                CStoredTransaction stx;
                BOOST_REQUIRE(wdb.ReadStoredTx(ao.outpoint.hash, stx));
                BOOST_REQUIRE(stx.GetBlind(ao.outpoint.n, blinding_factor_prevout.data()));
            }
        }
    }
    BOOST_REQUIRE(real_column < 5000);
    vpBlinds.push_back(blinding_factor_prevout.data());

    // Get blinding factor for change output commitment
    CAmount changeAmount = -1;
    uint8_t changeBlindOut[32] = {0};

    for (const auto &tmp_out : vecSend) {
        if (!tmp_out.fChange) {
            continue;
        }
        changeAmount = tmp_out.nAmount;
        memcpy(changeBlindOut, tmp_out.vBlind.data(), 32);
        vpOutCommits.push_back(tmp_out.commitment.data);
        break;
    }
    BOOST_REQUIRE(changeAmount > -1);

    uint8_t blindSum[32] = {0}; // Set by secp256k1_prepare_mlsag
    vpsk[nRows-1] = blindSum;
    vpBlinds.push_back(cctl.vSplitCommitBlindingKeys[0].begin());

    const uint8_t *pSplitCommit = &vDL[(1 + (nInputs+1) * nRingSize) * 32];
    BOOST_REQUIRE(0 == secp256k1_prepare_mlsag(&vM[0], blindSum,
        1, 1, nCols, nRows,
        &vpInCommits[0], &pSplitCommit, &vpBlinds[0]));

    uint256 txhash = mtx.GetHash();
    BOOST_REQUIRE(0 == secp256k1_generate_mlsag(secp256k1_ctx_blind, vKeyImages.data(), &vDL[0], &vDL[32],
        rand_seed, txhash.begin(), nCols, nRows, real_column, &vpsk[0], &vM[0]));

    // Should fail verification
    CTransaction ctx(mtx);
    BOOST_REQUIRE(!Consensus::CheckTxInputs(ctx, state, view, nSpendHeight, txfee));
    BOOST_REQUIRE(state.GetRejectReason() == "bad-anonin-dup-ki");
    BOOST_REQUIRE(!VerifyMLSAG(ctx, state));
    BOOST_REQUIRE(state.GetRejectReason() == "bad-anonin-dup-ki");
    }
    }


    // Verify duplicate keyimage in block fails
    CMutableTransaction mtx1, mtx2;
    {
    {
    LOCK(pwallet->cs_wallet);
    CCoinControl cctl;
    std::vector<COutputR> vAvailableCoins;
    pwallet->AvailableAnonCoins(vAvailableCoins, true, &cctl, 100000);
    BOOST_REQUIRE(vAvailableCoins.size() > 1);
    CAmount prevouts_sum = 0;
    for (const auto &output : vAvailableCoins) {
        const COutputRecord *pout = output.rtx->second.GetOutput(output.i);
        prevouts_sum += pout->nValue;
        cctl.Select(COutPoint(output.txhash, output.i));
        if (cctl.NumSelected() >= 1) {
            break;
        }
    }

    {
    CPubKey pk_toA;
    BOOST_REQUIRE(0 == pwallet->NewKeyFromAccount(pk_toA));

    std::vector<CTempRecipient> vecSend;
    CTxDestination dest = PKHash(pk_toA);
    vecSend.emplace_back(OUTPUT_STANDARD, prevouts_sum, dest);
    vecSend.back().fSubtractFeeFromAmount = true;

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    BOOST_REQUIRE(0 == pwallet->AddAnonInputs(wtx, rtx, vecSend, true, 3, 1, nFee, &cctl, sError));
    BOOST_REQUIRE(wtx.tx->vin.size() == 1);

    mtx1 = CMutableTransaction(*wtx.tx);
    }
    {
    CPubKey pk_toB;
    BOOST_REQUIRE(0 == pwallet->NewKeyFromAccount(pk_toB));

    std::vector<CTempRecipient> vecSend;
    CTxDestination dest = PKHash(pk_toB);
    vecSend.emplace_back(OUTPUT_STANDARD, prevouts_sum, dest);
    vecSend.back().fSubtractFeeFromAmount = true;

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, tx_new);
    CTransactionRecord rtx;
    CAmount nFee;
    BOOST_REQUIRE(0 == pwallet->AddAnonInputs(wtx, rtx, vecSend, true, 3, 1, nFee, &cctl, sError));
    BOOST_REQUIRE(wtx.tx->vin.size() == 1);

    mtx2 = CMutableTransaction(*wtx.tx);
    }
    }

    // Txns should be valid individually
    CTransaction tx1(mtx1), tx2(mtx2);
    int nSpendHeight = ::ChainActive().Tip()->nHeight;
    TxValidationState tx_state;
    tx_state.m_exploit_fix_1 = true;
    tx_state.m_exploit_fix_2 = true;
    tx_state.m_spend_height = nSpendHeight;
    CAmount txfee = 0;
    {
    LOCK(cs_main);
    CCoinsViewCache &tx_view = ::ChainstateActive().CoinsTip();
    BOOST_REQUIRE(Consensus::CheckTxInputs(tx1, tx_state, tx_view, nSpendHeight, txfee));
    BOOST_REQUIRE(VerifyMLSAG(tx1, tx_state));
    BOOST_REQUIRE(Consensus::CheckTxInputs(tx2, tx_state, tx_view, nSpendHeight, txfee));
    BOOST_REQUIRE(VerifyMLSAG(tx2, tx_state));
    }

    // Add to block
    std::unique_ptr<CBlockTemplate> pblocktemplate = pwallet->CreateNewBlock();
    BOOST_REQUIRE(pblocktemplate.get());
    pblocktemplate->block.vtx.push_back(MakeTransactionRef(mtx1));
    pblocktemplate->block.vtx.push_back(MakeTransactionRef(mtx2));

    size_t k, nTries = 10000;
    int nBestHeight = WITH_LOCK(cs_main, return ::ChainActive().Height());
    for (k = 0; k < nTries; ++k) {
        int64_t nSearchTime = GetAdjustedTime() & ~Params().GetStakeTimestampMask(nBestHeight+1);
        if (nSearchTime > pwallet->nLastCoinStakeSearchTime &&
            pwallet->SignBlock(pblocktemplate.get(), nBestHeight+1, nSearchTime)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    BOOST_REQUIRE(k < nTries);

    {
    CBlock *pblock = &pblocktemplate->block;
    BlockValidationState state;
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    BOOST_REQUIRE(!ProcessNewBlock(Params(), shared_pblock, state));
    BOOST_REQUIRE(state.GetRejectReason() == "bad-anonin-dup-ki");
    }

    // Should connect without bad tx
    pblocktemplate->block.vtx.pop_back();
    for (k = 0; k < nTries; ++k) {
        int64_t nSearchTime = GetAdjustedTime() & ~Params().GetStakeTimestampMask(nBestHeight+1);
        if (nSearchTime > pwallet->nLastCoinStakeSearchTime &&
            pwallet->SignBlock(pblocktemplate.get(), nBestHeight+1, nSearchTime)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    BOOST_REQUIRE(k < nTries);

    {
    CBlock *pblock = &pblocktemplate->block;
    BlockValidationState state;
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    BOOST_REQUIRE(ProcessNewBlock(Params(), shared_pblock, state));
    }
    BOOST_REQUIRE(WITH_LOCK(cs_main, return ::ChainActive().Height()) > nBestHeight);

    // Verify duplicate keyimage in chain fails
    {
    LOCK(cs_main);
    CCoinsViewCache &tx_view = ::ChainstateActive().CoinsTip();
    nSpendHeight = WITH_LOCK(cs_main, return ::ChainActive().Height());
    BOOST_REQUIRE(Consensus::CheckTxInputs(tx2, tx_state, tx_view, nSpendHeight, txfee));
    BOOST_REQUIRE(!VerifyMLSAG(tx2, tx_state));
    BOOST_REQUIRE(tx_state.GetRejectReason() == "bad-anonin-dup-ki");
    }
    }

    // Wait to add time for db flushes to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(1250));

    SetNumBlocksOfPeers(peer_blocks);
}

BOOST_AUTO_TEST_SUITE_END()
