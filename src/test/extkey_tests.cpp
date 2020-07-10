// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key/extkey.h>
#include <key_io.h>
#include <uint256.h>
#include <chainparams.h>
#include <util/strencodings.h>
#include <test/setup_common.h>
#include <streams.h>

#include <string>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(extkey_tests, ParticlBasicTestingSetup)

class FailTest
{
public:
    FailTest(std::string _sTest, int _rv) : sTest(_sTest), rv(_rv) {};
    std::string sTest;
    int rv;
};

FailTest failTests[] = {
    FailTest("", 3),
    FailTest("  ", 4),
    FailTest("abcd", 4),
    FailTest("M/3h/1111111111111111111111", 5),
    FailTest("/1/1", 7),
    FailTest("0/1/1/", 7),
    FailTest("0/1//1", 7),
    FailTest("m/2147483648h", 8),
    FailTest("m/4294967296", 5),
    FailTest("m/4294967297", 5),
    FailTest("0b0012", 4),
    FailTest("0x3Dg", 4),
    FailTest("m/4294967296", 5),
};

class PassTest
{
public:
    PassTest(std::string _sTest, int _rv, std::initializer_list<uint32_t> expect) : sTest(_sTest), rv(_rv), vExpect(expect.begin(), expect.end()) {};
    std::string sTest;
    int rv;
    std::vector<uint32_t> vExpect;
};

PassTest passTests[] = {
    PassTest("0", 0, { 0 }),
    PassTest("1", 0, { 1 }),
    PassTest("0/1", 0, { 0, 1 }),
    PassTest("1/0", 0, { 1, 0 }),
    PassTest("M/3", 0, { 3 }),
    PassTest("m/0h", 0, { 2147483648 }),
    PassTest("m/1H", 0, { 2147483649 }),
    PassTest("m/2'", 0, { 2147483650 }),
    PassTest("m/4294967295", 0, { 4294967295 }),
    PassTest("m/4/0b001/0xFe/3/0b010/0b010h", 0, { 4, 1, 254, 3, 2, 2147483650 }),
    PassTest("m/2147483647h", 0, { 4294967295 }),
    PassTest("0800/0xFh", 0, { 800, 2147483663 }),
};

void RunPathTest()
{
    int rv;

    std::vector<uint32_t> vPath;
    std::vector<uint32_t> vExpect;
    std::string sTest;

    // Tests expected to fail:
    int al = sizeof(failTests)/sizeof(FailTest);

    for (int i = 0; i < al; ++i)
    {
        FailTest &ft = failTests[i];
        rv = ExtractExtKeyPath(ft.sTest, vPath);
        BOOST_CHECK(rv == ft.rv);
    };

    char tooMuchData[513];
    memset(tooMuchData, '/', 512);
    tooMuchData[512] = '\0';
    sTest = std::string(tooMuchData);
    rv = ExtractExtKeyPath(sTest, vPath);
    BOOST_CHECK(rv == 2);

    // Tests expected to pass:
    al = sizeof(passTests)/sizeof(PassTest);

    std::stringstream ss, ssE;
    for (int i = 0; i < al; ++i)
    {
        PassTest &pt = passTests[i];
        rv = ExtractExtKeyPath(pt.sTest, vPath);

        ss.str("");
        for (std::vector<uint32_t>::iterator it = vPath.begin(); it != vPath.end(); ++it)
        {
            ss << *it;
            if (it != vPath.end()-1)
                ss << ", ";
        };

        ssE.str("");
        for (std::vector<uint32_t>::iterator it = pt.vExpect.begin(); it != pt.vExpect.end(); ++it)
        {
            ssE << *it;
            if (it != pt.vExpect.end()-1)
                ssE << ", ";
        };

        BOOST_CHECK(rv == pt.rv);
        BOOST_CHECK(vPath == pt.vExpect);
    };
}

class DeriveTestData
{
public:
    DeriveTestData(uint32_t _nDerives, std::string _vKey58, std::string _pKey58) : nDerives(_nDerives), vKey58(_vKey58), pKey58(_pKey58) { };

    uint32_t nDerives;
    std::string vKey58;
    std::string pKey58;
};

void RunDeriveTest(std::vector<DeriveTestData> &vData)
{
    int rv;
    CBitcoinExtKey extKey58;
    CExtKey evkeyM;
    CExtPubKey epkeyM;

    for (uint32_t k = 0; k < vData.size(); ++k)
    {
        DeriveTestData &dt = vData[k];

        if (dt.nDerives == 0)
        {
            // Set master

            BOOST_CHECK(0 == (rv = extKey58.Set58(dt.vKey58.c_str())));
            BOOST_CHECK(0 == (rv += abs(strcmp(extKey58.ToString().c_str(), dt.vKey58.c_str()))));

            evkeyM = extKey58.GetKey();
            BOOST_CHECK(0 == (rv += abs(strcmp(CBitcoinExtKey(evkeyM).ToString().c_str(), dt.vKey58.c_str()))));
            epkeyM = evkeyM.Neutered();

            BOOST_CHECK(0 == (rv += abs(strcmp(CBitcoinExtPubKey(epkeyM).ToString().c_str(), dt.pKey58.c_str()))));

            BOOST_CHECK(CBitcoinExtPubKey(epkeyM).ToString().c_str());

            if (rv != 0)
            {
                BOOST_MESSAGE("Set master failed, aborting test.");
                break;
            }
            continue;
        };


        CExtKey evkey[2], evkeyOut;
        CExtPubKey epkeyOut;
        evkey[0] = evkeyM;
        rv = 0;
        for (uint32_t d = 0; d < dt.nDerives; ++d)
        {
            rv += evkey[d % 2].Derive(evkey[(d+1) % 2], 1);
        }
        BOOST_CHECK(dt.nDerives == (uint32_t)rv);
        evkeyOut = evkey[dt.nDerives % 2];

        BOOST_CHECK(CBitcoinExtKey(evkeyOut).ToString().c_str());
        BOOST_MESSAGE("evkeyOut.nDepth " << (int)evkeyOut.nDepth);
        BOOST_CHECK(evkeyOut.nDepth == dt.nDerives % 256);

        BOOST_CHECK(0 == strcmp(CBitcoinExtKey(evkeyOut).ToString().c_str(), dt.vKey58.c_str()));

        epkeyOut = evkeyOut.Neutered();
        BOOST_CHECK(0 == strcmp(CBitcoinExtPubKey(epkeyOut).ToString().c_str(), dt.pKey58.c_str()));
    };

    return;
};

void RunDeriveTests()
{
    /*
        Must be able to derive deeper than the arbitrary ndepth field (255)
    */

    std::vector<DeriveTestData> vMainNetPairs = {
        DeriveTestData(0,
            std::string("XGHSTPgtqERy21V7QzFk4zmx5aUdcDZzfY7D99B8X4kuQZdHq1pJzDg9KtMCoPixi1z6wzdyzGBnX84BgPU4RXXjP2nj4itNagLZ5FULLqCamzng"),
            std::string("PGHSTWq7QxGFUTBgiPNvZ5KSZcsASoJLZwi5sCYCh86qRsPJFTP3nYaFnQHnwvWBeCxoQx1VSmSnXBy1So9tocovqop7VxkSE7W5paCnixDgYmsH")),
        /* TODO port this test to mainnet ghost
        DeriveTestData(350,
            std::string("XGHSTPgQfAN8aDi1FYMy1PeqJXNcbQQvvDaGHjxSP7RHHohaJU8Sx52uqD2Zy4JytGVo2939kg1ypr5RwZSRRj7NiuNyVrgnHiDZggD5yyimnURC"),
            std::string("PGHSTWpdEtCR2fQaYwV9VUCKnZm9Rz9GpdB91oKWZAmDK7TaiuhBkPw2HiyA7b6Z4z5k1rLTj6NHBGJTwPd32wfntvuS81PBhmiZsF4pNUjsAfpG")),
        */
    };

    std::vector<DeriveTestData> vTestNetPairs = {
        DeriveTestData(0,
            std::string("xparFdrwJK7K2nfYygX9DTNQ2jFEsVyZ4GSewx1HosK5xoeSahH9Y5U3s9muxZvvhzop2cB2THdY8GLvDSuvprvFe7irBSGC8SCg2kopTnkqPWi"),
            std::string("pparszDdEByd5kvHotS5WeLAiv5gp7b1YfUTs31TmudPuf1dHtos22oNJPmHT2NKyysyfqN56nFPVkUwZjPhK5zqLMucuT8g9dHXjnjsKufeSuVm")),
        DeriveTestData(1,
            std::string("xparFfqM6xibpb6fDtB6tLPNpC89yZejLSqW4CTaGbVkkws3VtRrw3siNhGBxuAFAy1C6rMbrbasWFsMSLho4imGzV1DFczz8ZfcDVuKLSj11kc"),
            std::string("pparszFbdzdENYiiv8djUKDBhhYZjDegiweri9Fv4NMaaT9qtp11jRmmxuJmj2guRodVqE1jj7vJxZUm2fzBCUPxfrvCAi5iD2SinpS3Vu1KTDZL")),

        DeriveTestData(350,
            std::string("xparJhpVV3WDMMgrKbzP8eoMQMf8m6T8nbyfhGJdVSexTvyrR1MToMxoma8GZRN3tfMTPnVwbVJ6mjKSkfLTvoucDtXVPaefovGGu5oQwNoJECr"),
            std::string("ppart3HanNi1z5VK7EMYkZXbgHi6i1BV8PozsnKm7bCjnA8xhj7wLJ5s4JBdodEmyCwRnwiSe66qx4fej5nkKTDioEGwKn1qoyJccJwDSBXEsZmM")),
    };
    CBitcoinExtKey extKey58;

    // Valid string
    BOOST_CHECK(0 == extKey58.Set58(vMainNetPairs[0].vKey58.c_str()));
    BOOST_CHECK(strcmp(extKey58.ToString().c_str(), vMainNetPairs[0].vKey58.c_str()) == 0);
    // Invalid string
    BOOST_CHECK(0 != extKey58.Set58(vMainNetPairs[0].vKey58.c_str()+3));

    RunDeriveTest(vMainNetPairs);


    // Fail testnet key on main
    BOOST_CHECK(0 != extKey58.Set58(vTestNetPairs[0].vKey58.c_str()));


    // Switch to testnet
    BOOST_MESSAGE("Entering Testnet");
    SelectParams(CBaseChainParams::TESTNET);

    // Pass testnet key on testnet
    BOOST_CHECK(0 == extKey58.Set58(vTestNetPairs[0].vKey58.c_str()));
    BOOST_CHECK(strcmp(extKey58.ToString().c_str(), vTestNetPairs[0].vKey58.c_str()) == 0);

    RunDeriveTest(vTestNetPairs);


    // Return to mainnet
    SelectParams(CBaseChainParams::MAIN);

    return;
};

void RunSerialiseTests()
{
    int64_t nTest;
    int64_t nTest0      = 0l;
    int64_t nTest4      = 1432035740l;
    int64_t nTest4_1    = 2189410940l; // 2039
    int64_t nTest5      = 4294967298l; // 2106
    int64_t nTest8      = -3l;

    BOOST_CHECK(0 == GetNumBytesReqForInt(nTest0));
    BOOST_CHECK(4 == GetNumBytesReqForInt(nTest4));
    BOOST_CHECK(4 == GetNumBytesReqForInt(nTest4_1)); // expect 4, no sign bit
    BOOST_CHECK(5 == GetNumBytesReqForInt(nTest5));
    BOOST_CHECK(8 == GetNumBytesReqForInt(nTest8));

    std::vector<uint8_t> v;
    SetCompressedInt64(v, nTest0);
    GetCompressedInt64(v, (uint64_t&)nTest);
    BOOST_CHECK(nTest0 == nTest);

    SetCompressedInt64(v, nTest5);
    GetCompressedInt64(v, (uint64_t&)nTest);
    BOOST_CHECK(nTest5 == nTest);

    SetCompressedInt64(v, nTest8);
    GetCompressedInt64(v, (uint64_t&)nTest);
    BOOST_CHECK(nTest8 == nTest);

    CStoredExtKey sk, sk_;
    CStoredExtKey skInvalid, skInvalid_;

    CExtKey58 eKey58;
    BOOST_CHECK(0 == eKey58.Set58("XGHSTPgtqERy21V7QzFk4zmx5aUdcDZzfY7D99B8X4kuQZdHq1pJzDg9KtMCoPixi1z6wzdyzGBnX84BgPU4RXXjP2nj4itNagLZ5FULLqCamzng"));

    sk.kp = eKey58.GetKey();
    sk.sLabel = "sk label";
    sk.nGenerated = 5;
    sk.nHGenerated = 6;
    sk.mapValue[EKVT_CREATED_AT] = SetCompressedInt64(v, nTest8);

    eKey58.SetKey(sk.kp, CChainParams::EXT_PUBLIC_KEY);
    BOOST_CHECK(eKey58.ToString() == "PGHSTWq7QxGFUTBgiPNvZ5KSZcsASoJLZwi5sCYCh86qRsPJFTP3nYaFnQHnwvWBeCxoQx1VSmSnXBy1So9tocovqop7VxkSE7W5paCnixDgYmsH");

    eKey58.SetKeyV(sk.kp);
    BOOST_CHECK(eKey58.ToString() == "XGHSTPgtqERy21V7QzFk4zmx5aUdcDZzfY7D99B8X4kuQZdHq1pJzDg9KtMCoPixi1z6wzdyzGBnX84BgPU4RXXjP2nj4itNagLZ5FULLqCamzng");


    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << sk << skInvalid;

    ss >> sk_;
    ss >> skInvalid_;

    BOOST_CHECK(sk.kp == sk_.kp);
    BOOST_CHECK(1 == sk_.kp.IsValidV());
    BOOST_CHECK(1 == sk_.kp.IsValidP());
    BOOST_CHECK(sk.sLabel == sk_.sLabel);
    BOOST_CHECK(sk.nGenerated == sk_.nGenerated);
    BOOST_CHECK(sk.nHGenerated == sk_.nHGenerated);
    BOOST_CHECK(nTest8 == GetCompressedInt64(sk_.mapValue[EKVT_CREATED_AT], (uint64_t&)nTest));

    BOOST_CHECK(0 == skInvalid.kp.IsValidV());
    BOOST_CHECK(0 == skInvalid.kp.IsValidP());



    // path

    std::vector<uint8_t> vPath;

    PushUInt32(vPath, 1);
    PushUInt32(vPath, 3);
    PushUInt32(vPath, 2);
    PushUInt32(vPath, 4294967295);

    std::string sPath;
    BOOST_CHECK(0 == PathToString(vPath, sPath, 'h'));
    BOOST_CHECK(sPath == "m/1/3/2/2147483647h");

    vPath.resize(0);
    PushUInt32(vPath, 1);
    PushUInt32(vPath, 4294967294);
    PushUInt32(vPath, 30);
    BOOST_CHECK(0 == PathToString(vPath, sPath));
    BOOST_CHECK(sPath == "m/1/2147483646'/30");


    // id
    CBitcoinAddress addr;
    CKeyID id = sk.GetID();
    CKeyID idTest;


    BOOST_CHECK(true == addr.Set(id, CChainParams::EXT_KEY_HASH)
        && addr.IsValid(CChainParams::EXT_KEY_HASH)
        && addr.GetKeyID(idTest, CChainParams::EXT_KEY_HASH));

    BOOST_CHECK(id == idTest);
    BOOST_CHECK_MESSAGE(addr.ToString() == "XKCGeD8yZd1jVH75rhxirhmizmn5uiHQGJ", addr.ToString());


    // Test DeriveNextKey

    CExtKey ev;
    CExtPubKey ep;
    uint32_t nChild=0;

    sk.nGenerated = 0;
    sk.nHGenerated = 0;
    BOOST_CHECK(0 == sk.DeriveNextKey(ev, nChild));
    BOOST_CHECK_MESSAGE(1 == sk.nGenerated, "nGenerated " << sk.nGenerated);
    sk.nGenerated = 0;
    BOOST_CHECK(0 == sk.DeriveNextKey(ep, nChild));

    BOOST_CHECK(ep.pubkey == ev.key.GetPubKey());


    id = ev.key.GetPubKey().GetID();
    addr.Set(id, CChainParams::EXT_KEY_HASH);
    BOOST_CHECK_MESSAGE(addr.ToString() == "XSuTNL78GorcrGY3hnqBECvho8ph1RZBFs", addr.ToString());

    sk.nGenerated = 1;
    BOOST_CHECK(0 == sk.DeriveNextKey(ev, nChild));
    id = ev.key.GetPubKey().GetID();
    addr.Set(id, CChainParams::EXT_KEY_HASH);
    BOOST_CHECK_MESSAGE(addr.ToString() == "XSRbnYaLS7PFsbN9Ajh8WoYEAdCRGe9kYF", addr.ToString());

    sk.nHGenerated = 0;
    BOOST_CHECK(0 == sk.DeriveNextKey(ev, nChild, true));
    id = ev.key.GetPubKey().GetID();
    addr.Set(id, CChainParams::EXT_KEY_HASH);
    BOOST_CHECK_MESSAGE(addr.ToString() == "XToHwqsjTNpTGWdx65346m3U5dy2EbKmd5", addr.ToString());
    BOOST_CHECK_MESSAGE(1 == sk.nHGenerated, "nHGenerated " << sk.nHGenerated);

    sk.nHGenerated = 1;
    BOOST_CHECK(0 == sk.DeriveNextKey(ev, nChild, true));
    id = ev.key.GetPubKey().GetID();
    addr.Set(id, CChainParams::EXT_KEY_HASH);
    BOOST_CHECK_MESSAGE(addr.ToString() == "XW4bxvTq1qfAB3NakPp4vAjc7A9VMFo4pN", addr.ToString());
    BOOST_CHECK_MESSAGE(2 == sk.nHGenerated, "nHGenerated " << sk.nHGenerated);

    sk.nHGenerated = 1;
    BOOST_CHECK(0 == sk.DeriveNextKey(ep, nChild, true));
    id = ev.key.GetPubKey().GetID();
    addr.Set(id, CChainParams::EXT_KEY_HASH);
    BOOST_CHECK_MESSAGE(addr.ToString() == "XW4bxvTq1qfAB3NakPp4vAjc7A9VMFo4pN", addr.ToString());
    BOOST_CHECK(ep.pubkey == ev.key.GetPubKey());


    CStoredExtKey skp = sk;
    skp.kp = skp.kp.Neutered();

    CKey k;

    sk.nGenerated = 1;
    BOOST_CHECK(0 == sk.DeriveNextKey(k, nChild, false));
    BOOST_CHECK_MESSAGE(nChild == 1, "nChild " << nChild);
    BOOST_CHECK_MESSAGE(HexStr(k.GetPubKey()) == "038bf05f82403b848f46434ac83326c20c3f8918159dc7889bed638b08370cc82a", "HexStr(k.GetPubKey()) " << HexStr(k.GetPubKey()));


    sk.nGenerated = 2;
    BOOST_CHECK(0 == sk.DeriveNextKey(k, nChild, false));
    BOOST_CHECK_MESSAGE(nChild == 2, "nChild " << nChild);
    BOOST_CHECK_MESSAGE(HexStr(k.GetPubKey()) == "035e248e5b1587809fe4787af388235b90e78a5601dcf506da0a08fa32381a0d07", "HexStr(k.GetPubKey()) " << HexStr(k.GetPubKey()));

    sk.nHGenerated = 2;
    BOOST_CHECK(0 == sk.DeriveNextKey(k, nChild, true));
    BOOST_CHECK_MESSAGE(nChild == 2147483650, "nChild " << nChild);
    BOOST_CHECK_MESSAGE(HexStr(k.GetPubKey()) == "0292ca892f0c6f469a089e46690bbec69e06c7c3e9224a25f6606f68f7d7634ee7", "HexStr(k.GetPubKey()) " << HexStr(k.GetPubKey()));

    // Can't derive keys from pubkeys
    skp.nGenerated = 1;
    BOOST_CHECK(1 == skp.DeriveNextKey(k, nChild, false));

    skp.nHGenerated = 1;
    BOOST_CHECK(1 == skp.DeriveNextKey(k, nChild, true));



    CPubKey pk;
    sk.nGenerated = 1;
    BOOST_CHECK(0 == sk.DeriveNextKey(pk, nChild, false));
    BOOST_CHECK_MESSAGE(nChild == 1, "nChild " << nChild);
    BOOST_CHECK_MESSAGE(HexStr(pk) == "038bf05f82403b848f46434ac83326c20c3f8918159dc7889bed638b08370cc82a", "HexStr(pk) " << HexStr(pk));

    sk.nHGenerated = 2;
    BOOST_CHECK(0 == sk.DeriveNextKey(pk, nChild, true));
    BOOST_CHECK_MESSAGE(nChild == 2147483650, "nChild " << nChild);
    BOOST_CHECK_MESSAGE(HexStr(pk) == "0292ca892f0c6f469a089e46690bbec69e06c7c3e9224a25f6606f68f7d7634ee7", "HexStr(pk) " << HexStr(pk));

    skp.nGenerated = 2;
    BOOST_CHECK(0 == skp.DeriveNextKey(pk, nChild, false));
    BOOST_CHECK_MESSAGE(nChild == 2, "nChild " << nChild);
    BOOST_CHECK_MESSAGE(HexStr(pk) == "035e248e5b1587809fe4787af388235b90e78a5601dcf506da0a08fa32381a0d07", "HexStr(pk) " << HexStr(pk));

    // Can't derive hardened pubkeys from pubkeys
    skp.nHGenerated = 1;
    BOOST_CHECK(1 == skp.DeriveNextKey(pk, nChild, true));


    // CBitcoinAddress tests
    // CBitcoinAddress always deals in public keys - should never expose a secret in an address



    CExtKeyPair kp, kpT;
    CTxDestination dest;

    BOOST_CHECK(0 == eKey58.Set58("XGHSTPgQfAN8aDi1FYMy1PeqJXNcbQQvvDaGHjxSP7RHHohaJU8Sx52uqD2Zy4JytGVo2939kg1ypr5RwZSRRj7NiuNyVrgnHiDZggD5yyimnURC"));
    kp = eKey58.GetKey();
    CBitcoinAddress addrB(kp);
    BOOST_CHECK(addrB.IsValid() == true);

    BOOST_CHECK(addr.Set(kp) == true);
    BOOST_CHECK(addr.IsValid() == true);
    BOOST_CHECK(addr.IsValid(CChainParams::EXT_SECRET_KEY) == false);
    BOOST_CHECK(addr.IsValid(CChainParams::EXT_PUBLIC_KEY) == true);
    BOOST_CHECK(addr.ToString() == "PGHSTWpdEtCR2fQaYwV9VUCKnZm9Rz9GpdB91oKWZAmDK7TaiuhBkPw2HiyA7b6Z4z5k1rLTj6NHBGJTwPd32wfntvuS81PBhmiZsF4pNUjsAfpG");
    dest = addr.Get();
    BOOST_CHECK(dest.type() == typeid(CExtKeyPair));
    kpT = boost::get<CExtKeyPair>(dest);
    /* TODO Fix this check on mainnet params
    BOOST_CHECK(kpT == kp);
    */

    // Switch to testnet
    SelectParams(CBaseChainParams::TESTNET);

    id = sk.GetID();
    BOOST_CHECK(true == addr.Set(id, CChainParams::EXT_KEY_HASH)
        && addr.IsValid(CChainParams::EXT_KEY_HASH)
        && addr.GetKeyID(idTest, CChainParams::EXT_KEY_HASH));

    BOOST_CHECK(id == idTest);
    BOOST_CHECK_MESSAGE(addr.ToString() == "xG9fgwcqaok4C9kTNicUvUeW23kZxrS1yF", addr.ToString());


    BOOST_CHECK(0 == eKey58.Set58("pparszDdEByd5kvHotS5WeLAiv5gp7b1YfUTs31TmudPuf1dHtos22oNJPmHT2NKyysyfqN56nFPVkUwZjPhK5zqLMucuT8g9dHXjnjsKufeSuVm"));
    kp = eKey58.GetKey();
    CBitcoinAddress addrC("xparFdrwJK7K2nfYygX9DTNQ2jFEsVyZ4GSewx1HosK5xoeSahH9Y5U3s9muxZvvhzop2cB2THdY8GLvDSuvprvFe7irBSGC8SCg2kopTnkqPWi");
    BOOST_CHECK(addrC.IsValid() == true);
    BOOST_CHECK(addrC.IsValid(CChainParams::EXT_PUBLIC_KEY) == true);

    BOOST_CHECK(addr.Set(kp) == true);
    BOOST_CHECK(addr.IsValid() == true);
    BOOST_CHECK(addr.IsValid(CChainParams::EXT_SECRET_KEY) == false);
    BOOST_CHECK(addr.IsValid(CChainParams::EXT_PUBLIC_KEY) == true);
    BOOST_CHECK(addr.ToString() == "pparszDdEByd5kvHotS5WeLAiv5gp7b1YfUTs31TmudPuf1dHtos22oNJPmHT2NKyysyfqN56nFPVkUwZjPhK5zqLMucuT8g9dHXjnjsKufeSuVm");
    dest = addr.Get();
    BOOST_CHECK(dest.type() == typeid(CExtKeyPair));
    kpT = boost::get<CExtKeyPair>(dest);
    BOOST_CHECK(kpT == kp);

    // Return to mainnet
    SelectParams(CBaseChainParams::MAIN);
};

BOOST_AUTO_TEST_CASE(extkey_path)
{
    RunPathTest();
}

BOOST_AUTO_TEST_CASE(extkey_derive)
{
    RunDeriveTests();
}

BOOST_AUTO_TEST_CASE(extkey_serialise)
{
    RunSerialiseTests();
}

BOOST_AUTO_TEST_CASE(extkey_regtest_keys)
{
    CExtKey58 ek58;

    // Switch to testnet
    SelectParams(CBaseChainParams::REGTEST);

    BOOST_CHECK(0 == ek58.Set58("pparszMzzW1247AwkKCH1MqneucXJfDoR3M5KoLsJZJpHkcjayf1xUMwPoTcTfUoQ32ahnkHhjvD2vNiHN5dHL6zmx8vR799JxgCw95APdkwuGm1",
        CChainParams::EXT_PUBLIC_KEY, &Params()));

    CExtPubKey ekp;
    assert(true == ek58.GetPubKey(ekp, &Params()));
    unsigned char temp[32];
    for (uint32_t k = 0; k < 10; ++k) {
        CPubKey out;
        BOOST_CHECK(true == ekp.pubkey.Derive(out, temp, k, ekp.chaincode));
        if (k == 9) {
            BOOST_CHECK(EncodeDestination(PKHash(out)) == "paKfZFn7TQaZKoY8nnwq5dNxyNG7dkrmpD");
        }
    }

    // Return to mainnet
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(extkey_account)
{
    CExtKeyAccount eka;
    uint160 i;
    i.SetHex("0x01");
    CKeyID idk = CKeyID(i);
    CEKAKey ekk(2, 3);

    BOOST_CHECK(eka.SaveKey(idk, ekk));
    BOOST_CHECK(HK_YES == eka.HaveSavedKey(idk));

    const CEKAKey *pak = nullptr;
    const CEKASCKey *pasc = nullptr;
    isminetype ismine;
    BOOST_CHECK(HK_YES == eka.HaveKey(idk, false, pak, pasc, ismine));
    BOOST_CHECK(pak != nullptr);
    BOOST_CHECK(pasc == nullptr);
    BOOST_CHECK(pak->nParent == 2);
    BOOST_CHECK(pak->nKey == 3);
}

BOOST_AUTO_TEST_CASE(extkey_misc_keys)
{
    uint32_t nTest = 1;
    BOOST_CHECK(!IsHardened(nTest));
    SetHardenedBit(nTest);
    BOOST_CHECK(IsHardened(nTest));
    ClearHardenedBit(nTest);
    BOOST_CHECK(!IsHardened(nTest));
}

BOOST_AUTO_TEST_SUITE_END()

