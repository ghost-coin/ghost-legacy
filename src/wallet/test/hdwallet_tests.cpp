// Copyright (c) 2017 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/hdwallet.h>

#include <wallet/test/hdwallet_test_fixture.h>
#include <base58.h>
#include <chainparams.h>
#include <smsg/smessage.h>
#include <smsg/crypter.h>
#include <blind.h>
#include <primitives/transaction.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>

#include <boost/test/unit_test.hpp>

extern bool CheckAnonOutput(CValidationState &state, const CTxOutRingCT *p);


BOOST_FIXTURE_TEST_SUITE(hdwallet_tests, HDWalletTestingSetup)

class Test1
{
public:
    Test1(std::string s1, std::string s2, int nH, std::string s3) : sPassphrase(s1), sSeed(s2), nHash(nH), sOutput(s3) {};
    std::string sPassphrase;
    std::string sSeed;
    int nHash;
    std::string sOutput;
};


std::vector<Test1> vTestVector1 = {
    Test1("crazy horse battery staple", "Bitcoin seed", 50000, "xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73"),
    Test1("doesn'tneedtobewords",       "Bitcoin seed", 50000, "xprv9s21ZrQH143K24uheQvx9etuBgxXfGZrBuHdmmZXQ1Gv9n1sXE2BE85PHRmSFixb1i8ngZFV6n4mufebUEg55n1epDFsFXKhQ4abU7gvThb")
};

BOOST_AUTO_TEST_CASE(new_ext_key)
{
    // Match keys from http://bip32.org/

    CHDWallet *pwallet = pwalletMain.get();

    for (auto it = vTestVector1.begin(); it != vTestVector1.end(); ++it)
    {
        CExtKey ekTest;

        BOOST_CHECK(0 == pwallet->ExtKeyNew32(ekTest, it->sPassphrase.c_str(), it->nHash, it->sSeed.c_str()));

        CExtKeyPair ekp(ekTest);
        CExtKey58 ek58;
        ek58.SetKey(ekp, CChainParams::EXT_SECRET_KEY_BTC);
        BOOST_CHECK(ek58.ToString() == it->sOutput);
    };
}

static const std::string strSecret1C("GzFRfngjf5aHMuAzWDZWzJ8eYqMzp29MmkCp6NgzkXFibrh45tTc");
static const std::string strSecret2C("H5hDgLvFjLcZG9jyxkUTJ28P6N5T7iMBQ79boMuaPafxXuy8hb9n");

BOOST_AUTO_TEST_CASE(stealth)
{
    CHDWallet *pwallet = pwalletMain.get();

    ECC_Start_Stealth();
    CStealthAddress sx;
    BOOST_CHECK(true == sx.SetEncoded("SPGyji8uZFip6H15GUfj6bsutRVLsCyBFL3P7k7T7MUDRaYU8GfwUHpfxonLFAvAwr2RkigyGfTgWMfzLAAP8KMRHq7RE8cwpEEekH"));

    CAmount nValue = 1;

    std::string strError;
    std::string sNarr;


    // No bitfield, no narration
    std::vector<CTempRecipient> vecSend;
    CTempRecipient r;
    r.nType = OUTPUT_STANDARD;
    r.SetAmount(nValue);
    r.fSubtractFeeFromAmount = false;
    r.address = sx;
    r.sNarration = sNarr;
    vecSend.push_back(r);

    BOOST_CHECK(0 == pwallet->ExpandTempRecipients(vecSend, NULL, strError));
    BOOST_CHECK(2 == vecSend.size());
    BOOST_CHECK(34 == vecSend[1].vData.size());


    // No bitfield, with narration
    vecSend.clear();
    sNarr = "test narration";
    r.sNarration = sNarr;
    vecSend.push_back(r);
    BOOST_CHECK(0 == pwallet->ExpandTempRecipients(vecSend, NULL, strError));
    BOOST_CHECK(2 == vecSend.size());
    BOOST_REQUIRE(51 == vecSend[1].vData.size());
    BOOST_REQUIRE(vecSend[1].vData[34] == DO_NARR_CRYPT);

    CBitcoinSecret bsecret1;
    BOOST_CHECK(bsecret1.SetString(strSecret1C));
    //BOOST_CHECK(bsecret2.SetString(strSecret2C));

    CKey sScan = bsecret1.GetKey();

    CKey sShared;
    ec_point pkExtracted;
    ec_point vchEphemPK(vecSend[1].vData.begin() + 1, vecSend[1].vData.begin() + 34);
    std::vector<uint8_t> vchENarr(vecSend[1].vData.begin() + 35, vecSend[1].vData.end());


    BOOST_REQUIRE(StealthSecret(sScan, vchEphemPK, sx.spend_pubkey, sShared, pkExtracted) == 0);

    SecMsgCrypter crypter;
    crypter.SetKey(sShared.begin(), &vchEphemPK[0]);
    std::vector<uint8_t> vchNarr;
    BOOST_REQUIRE(crypter.Decrypt(&vchENarr[0], vchENarr.size(), vchNarr));
    std::string sNarrRecovered = std::string(vchNarr.begin(), vchNarr.end());
    BOOST_CHECK(sNarr == sNarrRecovered);


    // With bitfield, no narration
    vecSend.clear();
    sNarr = "";
    sx.prefix.number_bits = 5;
    sx.prefix.bitfield = 0xaaaaaaaa;
    r.address = sx;
    r.sNarration = sNarr;
    vecSend.push_back(r);
    BOOST_CHECK(0 == pwallet->ExpandTempRecipients(vecSend, NULL, strError));
    BOOST_CHECK(2 == vecSend.size());
    BOOST_REQUIRE(39 == vecSend[1].vData.size());
    BOOST_CHECK(vecSend[1].vData[34] == DO_STEALTH_PREFIX);
    uint32_t prefix, mask = SetStealthMask(sx.prefix.number_bits);
    memcpy(&prefix, &vecSend[1].vData[35], 4);

    BOOST_CHECK((prefix & mask) == (sx.prefix.bitfield & mask));


    // With bitfield, with narration
    vecSend.clear();
    sNarr = "another test narration";
    sx.prefix.number_bits = 18;
    sx.prefix.bitfield = 0xaaaaaaaa;
    r.address = sx;
    r.sNarration = sNarr;
    vecSend.push_back(r);
    BOOST_CHECK(0 == pwallet->ExpandTempRecipients(vecSend, NULL, strError));
    BOOST_CHECK(2 == vecSend.size());
    BOOST_REQUIRE(72 == vecSend[1].vData.size());

    BOOST_CHECK(vecSend[1].vData[34] == DO_STEALTH_PREFIX);
    mask = SetStealthMask(sx.prefix.number_bits);
    memcpy(&prefix, &vecSend[1].vData[35], 4);

    BOOST_CHECK((prefix & mask) == (sx.prefix.bitfield & mask));

    BOOST_CHECK(vecSend[1].vData[39] == DO_NARR_CRYPT);
    vchEphemPK.resize(33);
    memcpy(&vchEphemPK[0], &vecSend[1].vData[1], 33);

    vchENarr = std::vector<uint8_t>(vecSend[1].vData.begin() + 40, vecSend[1].vData.end());


    BOOST_REQUIRE(StealthSecret(sScan, vchEphemPK, sx.spend_pubkey, sShared, pkExtracted) == 0);

    crypter.SetKey(sShared.begin(), &vchEphemPK[0]);
    BOOST_REQUIRE(crypter.Decrypt(&vchENarr[0], vchENarr.size(), vchNarr));
    sNarrRecovered = std::string(vchNarr.begin(), vchNarr.end());
    BOOST_CHECK(sNarr == sNarrRecovered);


    ECC_Stop_Stealth();
}

BOOST_AUTO_TEST_CASE(stealth_key_index)
{
    CHDWallet *pwallet = pwalletMain.get();

    //ECC_Start_Stealth();
    CStealthAddress sx;
    BOOST_CHECK(sx.SetEncoded("SPGyji8uZFip6H15GUfj6bsutRVLsCyBFL3P7k7T7MUDRaYU8GfwUHpfxonLFAvAwr2RkigyGfTgWMfzLAAP8KMRHq7RE8cwpEEekH"));

    CStealthAddressIndexed sxi;
    uint32_t sxId;
    sx.ToRaw(sxi.addrRaw);
    BOOST_CHECK(pwallet->GetStealthKeyIndex(sxi, sxId));
    BOOST_CHECK(sxId == 1);


    BOOST_CHECK(sx.SetEncoded("SPGx7SrLpMcMUjJhQkMp7D8eRAxzVj34StgQdYHr9887nCNBAiUTr4eiJKunzDaBxUqTWGX1sCCJxvUH9WG1JkJw9o15Xn2JSjnpD9"));
    sx.ToRaw(sxi.addrRaw);
    BOOST_CHECK(pwallet->GetStealthKeyIndex(sxi, sxId));
    BOOST_CHECK(sxId == 2);

    BOOST_CHECK(sx.SetEncoded("SPGwdFXLfjt3yQLzVhwbQLriSBbSF3gbmBsTDtA4Sjkz5aCDvmPgw3EqT51YqbxanMzFmAUSWtvCheFvUeWc56QH7sYD4nUKVX8kz2"));
    sx.ToRaw(sxi.addrRaw);
    BOOST_CHECK(pwallet->GetStealthKeyIndex(sxi, sxId));
    BOOST_CHECK(sxId == 3);

    CStealthAddress sxOut;
    BOOST_CHECK(pwallet->GetStealthByIndex(2, sxOut));
    BOOST_CHECK(sxOut.ToString() == "SPGx7SrLpMcMUjJhQkMp7D8eRAxzVj34StgQdYHr9887nCNBAiUTr4eiJKunzDaBxUqTWGX1sCCJxvUH9WG1JkJw9o15Xn2JSjnpD9");


    BOOST_CHECK(sx.SetEncoded("SPGyji8uZFip6H15GUfj6bsutRVLsCyBFL3P7k7T7MUDRaYU8GfwUHpfxonLFAvAwr2RkigyGfTgWMfzLAAP8KMRHq7RE8cwpEEekH"));
    sx.ToRaw(sxi.addrRaw);
    BOOST_CHECK(pwallet->GetStealthKeyIndex(sxi, sxId));
    BOOST_CHECK(sxId == 1);


    CHDWalletDB wdb(pwallet->GetDBHandle(), "r+");
    uint160 hash;
    uint32_t nIndex;
    for (size_t k = 0; k < 512; ++k)
    {
        LOCK(pwallet->cs_wallet);
        pwallet->IndexStealthKey(&wdb, hash, sxi, nIndex);
    };
    BOOST_CHECK(nIndex == 515);

    //ECC_Stop_Stealth();
}

void makeNewStealthKey(CStealthAddress &sxAddr, CBasicKeyStore &keystore)
{
    InsecureNewKey(sxAddr.scan_secret, true);

    CKey spend_secret;
    InsecureNewKey(spend_secret, true);
    //sxAddr.spend_secret_id = spend_secret.GetPubKey().GetID();

    SecretToPublicKey(sxAddr.scan_secret, sxAddr.scan_pubkey);
    SecretToPublicKey(spend_secret, sxAddr.spend_pubkey);

    // verify
    CPubKey pkTemp = sxAddr.scan_secret.GetPubKey();
    BOOST_CHECK(pkTemp.size() == EC_COMPRESSED_SIZE);
    BOOST_CHECK(memcmp(&sxAddr.scan_pubkey[0], pkTemp.begin(), EC_COMPRESSED_SIZE) == 0);

    pkTemp = spend_secret.GetPubKey();
    BOOST_CHECK(pkTemp.size() == EC_COMPRESSED_SIZE);
    BOOST_CHECK(pkTemp.size() == EC_COMPRESSED_SIZE);
    BOOST_CHECK(memcmp(&sxAddr.spend_pubkey[0], pkTemp.begin(), EC_COMPRESSED_SIZE) == 0);

    keystore.AddKeyPubKey(spend_secret, pkTemp);
}

BOOST_AUTO_TEST_CASE(ext_key_index)
{
    CHDWallet *pwallet = pwalletMain.get();

    CHDWalletDB wdb(pwallet->GetDBHandle(), "r+");
    CKeyID dummy;
    uint32_t nIndex;
    for (size_t k = 0; k < 512; ++k)
    {
        LOCK(pwallet->cs_wallet);
        pwallet->ExtKeyNewIndex(&wdb, dummy, nIndex);
    };
    BOOST_CHECK(nIndex == 512);
}

BOOST_AUTO_TEST_CASE(test_TxOutRingCT)
{
    SelectParams(CBaseChainParams::TESTNET);
    CHDWallet *wallet = pwalletMain.get();

    SeedInsecureRand();
    CBasicKeyStore keystore;
    ECC_Start_Stealth();

    CStealthAddress sxAddr;
    makeNewStealthKey(sxAddr, keystore);

    CKey sEphem;
    CKey secretShared;
    ec_point pkSendTo;

    // Send, secret = ephem_secret, pubkey = scan_pubkey
    // NOTE: StealthSecret can fail if hash is out of range, retry with new ephemeral key
    int k, nTries = 24;
    for (k = 0; k < nTries; ++k)
    {
        InsecureNewKey(sEphem, true);
        if (StealthSecret(sEphem, sxAddr.scan_pubkey, sxAddr.spend_pubkey, secretShared, pkSendTo) == 0)
            break;
    };
    BOOST_CHECK_MESSAGE(k < nTries, "StealthSecret failed.");
    BOOST_CHECK(pkSendTo.size() == EC_COMPRESSED_SIZE);

    ec_point ephem_pubkey;
    CPubKey pkTemp = sEphem.GetPubKey();
    BOOST_CHECK(pkTemp.size() == EC_COMPRESSED_SIZE);
    ephem_pubkey.resize(EC_COMPRESSED_SIZE);
    memcpy(&ephem_pubkey[0], pkTemp.begin(), EC_COMPRESSED_SIZE);

    CKey secretShared_verify;
    ec_point pkSendTo_verify;

    // Receive, secret = scan_secret, pubkey = ephem_pubkey
    BOOST_CHECK(StealthSecret(sxAddr.scan_secret, ephem_pubkey, sxAddr.spend_pubkey, secretShared_verify, pkSendTo_verify) == 0);

    BOOST_CHECK(pkSendTo == pkSendTo_verify);
    BOOST_CHECK(secretShared == secretShared_verify);

    CKeyID iSpend = sxAddr.GetSpendKeyID();
    CKey kSpend;
    BOOST_CHECK(keystore.GetKey(iSpend, kSpend));
    CKey kSpendOut;
    BOOST_CHECK(StealthSharedToSecretSpend(secretShared_verify, kSpend, kSpendOut) == 0);
    pkTemp = kSpendOut.GetPubKey();
    BOOST_CHECK(CPubKey(pkSendTo) == pkTemp);

    CKey kSpendOut_test2;
    BOOST_CHECK(StealthSecretSpend(sxAddr.scan_secret, ephem_pubkey, kSpend, kSpendOut_test2) == 0);
    pkTemp = kSpendOut_test2.GetPubKey();
    BOOST_CHECK(CPubKey(pkSendTo) == pkTemp);

    BOOST_MESSAGE("----------------Setup Recipient---------------------\n");
    CTempRecipient r;
    r.nType = OUTPUT_RINGCT;
    CAmount nValue = 20*COIN;
    r.SetAmount(nValue);
    r.fSubtractFeeFromAmount = true;
    r.sEphem = sEphem;
    r.pkTo = CPubKey(pkSendTo);
    CKeyID idTo = r.pkTo.GetID();
    r.scriptPubKey = GetScriptForDestination(idTo);
    r.nStealthPrefix = FillStealthPrefix(sxAddr.prefix.number_bits, sxAddr.prefix.bitfield);
    r.vBlind.resize(32);
    GetStrongRandBytes(&r.vBlind[0], 32);
    BOOST_CHECK_MESSAGE(r.pkTo.IsValid(), "pubkeyto is not valid");

    BOOST_MESSAGE("---------------- Make RingCT Output : SetCTOutVData ---------------------\n");
    auto txout = MAKE_OUTPUT<CTxOutRingCT>();
    txout->pk = r.pkTo;

    CPubKey pkEphem = r.sEphem.GetPubKey();
    SetCTOutVData(txout->vData, pkEphem, r.nStealthPrefix);

    BOOST_MESSAGE("---------------- Make RingCT Output : AddCTData ---------------------\n");
    std::string strError;
    ECC_Start_Blinding();
    BOOST_CHECK_MESSAGE(wallet->AddCTData(txout.get(), r, strError) == 0, "failed to add CT Data");

    BOOST_MESSAGE("---------------- Checking RingCT Output---------------------\n");
    CValidationState state;
    BOOST_CHECK_MESSAGE(CheckAnonOutput(state, (CTxOutRingCT*)txout.get()), "failed to check ringct output");

    BOOST_MESSAGE("---------------- Serialize Transaction with No Segwit ---------------------\n");
    CMutableTransaction tx;
    tx.vpout.emplace_back(txout);
    tx.nVersion = 2|PARTICL_TXN_VERSION;
    BOOST_CHECK_MESSAGE(tx.IsParticlVersion(), "failed IsParticlVersion");

    //The peer that sends the block sets the version that the data stream will use!
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION|SERIALIZE_TRANSACTION_NO_WITNESS);
    ss << tx;

    BOOST_MESSAGE("---------------- Deserialize Transaction ---------------------\n");
    CMutableTransaction txCheck;
    ss >> txCheck;
    BOOST_CHECK_MESSAGE(!txCheck.HasWitness(), "deserialize shows witness");
    auto txout_check = txCheck.vpout.at(0);
    BOOST_CHECK_MESSAGE(txout_check->GetType() == OUTPUT_RINGCT, "deserialized output is not ringct");

    BOOST_MESSAGE("---------------- Check RingCT Output ---------------------\n");
    BOOST_CHECK_MESSAGE(!CheckAnonOutput(state, (CTxOutRingCT*)txout_check.get()), "passed check ringct output");

    ECC_Stop_Stealth();
}



BOOST_AUTO_TEST_SUITE_END()
