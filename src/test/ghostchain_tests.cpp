// Copyright (c) 2017-2021 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/setup_common.h>
#include <net.h>
#include <script/signingprovider.h>
#include <script/script.h>
#include <consensus/validation.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <key/extkey.h>
#include <pos/kernel.h>
#include <chainparams.h>
#include <blind.h>

#include <script/sign.h>
#include <policy/policy.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(ghostchain_tests, ParticlBasicTestingSetup)


BOOST_AUTO_TEST_CASE(oldversion_test)
{
    CBlock blk, blkOut;
    blk.nTime = 1487406900;

    CMutableTransaction txn;
    blk.vtx.push_back(MakeTransactionRef(txn));

    CDataStream ss(SER_DISK, 0);

    ss << blk;
    ss >> blkOut;

    BOOST_CHECK(blk.vtx[0]->nVersion == blkOut.vtx[0]->nVersion);
}

BOOST_AUTO_TEST_CASE(signature_test)
{
    SeedInsecureRand();
    FillableSigningProvider keystore;

    CKey k;
    InsecureNewKey(k, true);
    keystore.AddKey(k);

    CPubKey pk = k.GetPubKey();
    CKeyID id = pk.GetID();

    CMutableTransaction txn;
    txn.nVersion = GHOST_TXN_VERSION;
    txn.nLockTime = 0;

    int nBlockHeight = 22;
    OUTPUT_PTR<CTxOutData> out0 = MAKE_OUTPUT<CTxOutData>();
    out0->vData = SetCompressedInt64(out0->vData, nBlockHeight);
    txn.vpout.push_back(out0);

    CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(id) << OP_EQUALVERIFY << OP_CHECKSIG;
    OUTPUT_PTR<CTxOutStandard> out1 = MAKE_OUTPUT<CTxOutStandard>();
    out1->nValue = 10000;
    out1->scriptPubKey = script;
    txn.vpout.push_back(out1);

    CMutableTransaction txn2;
    txn2.nVersion = GHOST_TXN_VERSION;
    txn2.vin.push_back(CTxIn(txn.GetHash(), 0));

    std::vector<uint8_t> vchAmount(8);
    memcpy(&vchAmount[0], &out1->nValue, 8);

    SignatureData sigdata;
    BOOST_CHECK(ProduceSignature(keystore, MutableTransactionSignatureCreator(&txn2, 0, vchAmount, SIGHASH_ALL), script, sigdata));

    ScriptError serror = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(txn2.vin[0].scriptSig, out1->scriptPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker(&txn2, 0, vchAmount), &serror));
    BOOST_CHECK(serror == SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(ghostchain_test)
{
    SeedInsecureRand();
    FillableSigningProvider keystore;

    CKey k;
    InsecureNewKey(k, true);
    keystore.AddKey(k);

    CPubKey pk = k.GetPubKey();
    CKeyID id = pk.GetID();

    CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(id) << OP_EQUALVERIFY << OP_CHECKSIG;

    CBlock blk;
    blk.nVersion = GHOST_BLOCK_VERSION;
    blk.nTime = 1487406900;

    CMutableTransaction txn;
    txn.nVersion = GHOST_TXN_VERSION;
    txn.SetType(TXN_COINBASE);
    txn.nLockTime = 0;
    OUTPUT_PTR<CTxOutStandard> out0 = MAKE_OUTPUT<CTxOutStandard>();
    out0->nValue = 10000;
    out0->scriptPubKey = script;
    txn.vpout.push_back(out0);


    blk.vtx.push_back(MakeTransactionRef(txn));

    bool mutated;
    blk.hashMerkleRoot = BlockMerkleRoot(blk, &mutated);
    blk.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(blk, &mutated);


    CDataStream ss(SER_DISK, 0);
    ss << blk;

    CBlock blkOut;
    ss >> blkOut;

    BOOST_CHECK(blk.hashMerkleRoot == blkOut.hashMerkleRoot);
    BOOST_CHECK(blk.hashWitnessMerkleRoot == blkOut.hashWitnessMerkleRoot);
    BOOST_CHECK(blk.nTime == blkOut.nTime && blkOut.nTime == 1487406900);

    BOOST_CHECK(TXN_COINBASE == blkOut.vtx[0]->GetType());

    CMutableTransaction txnSpend;

    txnSpend.nVersion = GHOST_BLOCK_VERSION;
}

BOOST_AUTO_TEST_CASE(varints)
{
    // encode

    uint8_t c[128];
    std::vector<uint8_t> v;

    size_t size = 0;
    for (int i = 0; i < 100000; i++) {
        size_t sz = GetSizeOfVarInt<VarIntMode::NONNEGATIVE_SIGNED>(i);
        BOOST_CHECK(sz = PutVarInt(c, i));
        BOOST_CHECK(0 == PutVarInt(v, i));
        BOOST_CHECK(0 == memcmp(c, &v[size], sz));
        size += sz;
        BOOST_CHECK(size == v.size());
    }

    for (uint64_t i = 0;  i < 100000000000ULL; i += 999999937) {
        BOOST_CHECK(0 == PutVarInt(v, i));
        size += GetSizeOfVarInt<VarIntMode::DEFAULT>(i);
        BOOST_CHECK(size == v.size());
    }


    // decode
    size_t nB = 0, o = 0;
    for (int i = 0; i < 100000; i++) {
        uint64_t j = -1;
        BOOST_CHECK(0 == GetVarInt(v, o, j, nB));
        BOOST_CHECK_MESSAGE(i == (int)j, "decoded:" << j << " expected:" << i);
        o += nB;
    }

    for (uint64_t i = 0;  i < 100000000000ULL; i += 999999937) {
        uint64_t j = -1;
        BOOST_CHECK(0 == GetVarInt(v, o, j, nB));
        BOOST_CHECK_MESSAGE(i == j, "decoded:" << j << " expected:" << i);
        o += nB;
    }
}

BOOST_AUTO_TEST_CASE(mixed_input_types)
{
    CMutableTransaction txn;
    txn.nVersion = GHOST_TXN_VERSION;
    BOOST_CHECK(txn.IsGhostVersion());

    CAmount txfee;
    int nSpendHeight = 1;
    CCoinsView viewDummy;
    CCoinsViewCache inputs(&viewDummy);

    CMutableTransaction txnPrev;
    txnPrev.nVersion = GHOST_TXN_VERSION;
    BOOST_CHECK(txnPrev.IsGhostVersion());

    CScript scriptPubKey;
    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN, scriptPubKey));
    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(2 * COIN, scriptPubKey));
    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutCT>());
    txnPrev.vpout.push_back(MAKE_OUTPUT<CTxOutCT>());

    CTransaction txnPrev_c(txnPrev);
    AddCoins(inputs, txnPrev_c, 1);

    uint256 prevHash = txnPrev_c.GetHash();

    std::vector<std::pair<std::vector<int>, bool> > tests = {
        std::make_pair( (std::vector<int>) {0 }, true),
        std::make_pair( (std::vector<int>) {0, 1}, true),
        std::make_pair( (std::vector<int>) {0, 2}, false),
        std::make_pair( (std::vector<int>) {0, 1, 2}, false),
        std::make_pair( (std::vector<int>) {2}, true),
        std::make_pair( (std::vector<int>) {2, 3}, true),
        std::make_pair( (std::vector<int>) {2, 3, 1}, false),
        std::make_pair( (std::vector<int>) {-1}, true),
        std::make_pair( (std::vector<int>) {-1, -1}, true),
        std::make_pair( (std::vector<int>) {2, -1}, false),
        std::make_pair( (std::vector<int>) {0, -1}, false),
        std::make_pair( (std::vector<int>) {0, 0, -1}, false),
        std::make_pair( (std::vector<int>) {0, 2, -1}, false)
    };

    for (auto t : tests) {
        txn.vin.clear();

        for (auto ti : t.first) {
            if (ti < 0)  {
                CTxIn ai;
                ai.prevout.n = COutPoint::ANON_MARKER;
                ai.SetAnonInfo(1, 1);

                std::vector<uint8_t> vpkm, vki(33, 0);
                PutVarInt(vpkm, 1);
                ai.scriptWitness.stack.emplace_back(vpkm);
                ai.scriptData.stack.emplace_back(vki);
                txn.vin.push_back(ai);
                continue;
            }
            txn.vin.push_back(CTxIn(prevHash, ti));
        }

        CTransaction tx_c(txn);
        CValidationState state;
        Consensus::CheckTxInputs(tx_c, state, inputs, nSpendHeight, txfee);

        if (t.second) {
            BOOST_CHECK(state.GetRejectReason() != "mixed-input-types");
        } else {
            BOOST_CHECK(state.GetRejectReason() == "mixed-input-types");
        }
    }
}

//Test block reward over the years on GHOST
BOOST_AUTO_TEST_CASE(blockreward_at_height_test)
{
    const int64_t nBlocksPerYear = (365 * 24 * 60 * 60) / Params().GetTargetSpacing();

    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 0), 600000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 1), 600000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 2), 570000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 3), 540000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 4), 516000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 5), 486000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 6), 462000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 7), 444000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 8), 420000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 9), 396000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 10), 378000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 11), 360000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 12), 342000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 13), 324000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 14), 306000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 15), 294000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 16), 276000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 17), 264000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 18), 252000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 19), 240000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 20), 228000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 21), 216000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 22), 204000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 23), 192000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 24), 186000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 25), 174000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 26), 168000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 27), 156000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 28), 150000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 29), 144000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 30), 138000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 31), 126000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 32), 120000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 33), 114000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 34), 108000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 35), 102000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 36), 102000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 37), 96000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 38), 90000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 39), 84000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 40), 84000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 41), 78000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 42), 72000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 43), 72000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 44), 66000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 45), 60000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 46), 60000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 47), 60000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 48), 60000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 49), 60000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtHeight(nBlocksPerYear * 50), 60000000);
}

BOOST_AUTO_TEST_CASE(blockreward_at_year_test)
{
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(0), 600000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(1), 600000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(2), 570000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(3), 540000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(4), 516000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(5), 486000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(6), 462000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(7), 444000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(8), 420000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(9), 396000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(10), 378000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(11), 360000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(12), 342000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(13), 324000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(14), 306000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(15), 294000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(16), 276000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(17), 264000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(18), 252000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(19), 240000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(20), 228000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(21), 216000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(22), 204000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(23), 192000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(24), 186000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(25), 174000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(26), 168000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(27), 156000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(28), 150000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(29), 144000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(30), 138000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(31), 126000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(32), 120000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(33), 114000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(34), 108000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(35), 102000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(36), 102000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(37), 96000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(38), 90000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(39), 84000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(40), 84000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(41), 78000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(42), 72000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(43), 72000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(44), 66000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(45), 60000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(46), 60000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(47), 60000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(48), 60000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(49), 60000000);
    BOOST_CHECK_EQUAL(Params().GetProofOfStakeRewardAtYear(50), 60000000);
}

BOOST_AUTO_TEST_SUITE_END()
