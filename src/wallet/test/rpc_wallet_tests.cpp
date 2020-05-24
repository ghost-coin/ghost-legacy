// Copyright (c) 2013-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/client.h>
#include <rpc/rpcutil.h>

#include <key_io.h>
#include <validation.h>
#include <wallet/wallet.h>

#include <wallet/test/wallet_test_fixture.h>

#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

using namespace std;

//extern JSONRPCRequest createArgs(int nRequired, const char* address1 = NULL, const char* address2 = nullptr);

BOOST_FIXTURE_TEST_SUITE(rpc_wallet_tests, WalletTestingSetup)
/*
BOOST_AUTO_TEST_CASE(rpc_addmultisig)
{
    rpcfn_type addmultisig = tableRPC["addmultisigaddress"]->actor;

    // old, 65-byte-long:
    const char address1Hex[] = "0434e3e09f49ea168c5bbf53f877ff4206923858aab7c7e1df25bc263978107c95e35065a27ef6f1b27222db0ec97e0e895eaca603d3ee0d4c060ce3d8a00286c8";
    // new, compressed:
    const char address2Hex[] = "0388c2037017c62240b6b72ac1a2a5f94da790596ebd06177c8572752922165cb4";

    UniValue v;
    CBitcoinAddress address;
    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex, address2Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(2, address1Hex, address2Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_THROW(addmultisig(createArgs(0), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(1), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(2, address1Hex), false), runtime_error);

    BOOST_CHECK_THROW(addmultisig(createArgs(1, ""), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(1, "NotAValidPubkey"), false), runtime_error);

    string short1(address1Hex, address1Hex + sizeof(address1Hex) - 2); // last byte missing
    BOOST_CHECK_THROW(addmultisig(createArgs(2, short1.c_str()), false), runtime_error);

    string short2(address1Hex + 1, address1Hex + sizeof(address1Hex)); // first byte missing
    BOOST_CHECK_THROW(addmultisig(createArgs(2, short2.c_str()), false), runtime_error);
}
*/
BOOST_AUTO_TEST_CASE(rpc_wallet)
{
    // Test RPC calls for various wallet statistics
    UniValue r;
    CPubKey demoPubkey;
    CBitcoinAddress demoAddress;
    UniValue retValue;
    string strAccount = "walletDemoAccount";
    util::Ref context{m_node};

    // TODO: add new master key here
    return;

    CBitcoinAddress setaccountDemoAddress;
    {
        LOCK(m_wallet.cs_wallet);

        WalletBatch walletdb(m_wallet.GetDBHandle());
        auto spk_man = m_wallet.GetLegacyScriptPubKeyMan();
        assert(spk_man);
        LOCK(spk_man->cs_KeyStore);
        demoPubkey = spk_man->GenerateNewKey(walletdb, spk_man->m_hd_chain, false);
        demoAddress = CBitcoinAddress(CTxDestination(PKHash(demoPubkey)));
        string strPurpose = "receive";
        BOOST_CHECK_NO_THROW({ /*Initialize Wallet with an account */
            m_wallet.SetAddressBook(PKHash(demoPubkey), strAccount, strPurpose);
        });
    }

    /*********************************
     *      getbalance
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getbalance", context));
    BOOST_CHECK_NO_THROW(CallRPC("getbalance " + demoAddress.ToString(), context));

    /*********************************
     *      listunspent
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listunspent", context));
    BOOST_CHECK_THROW(CallRPC("listunspent string", context), runtime_error);
    BOOST_CHECK_THROW(CallRPC("listunspent 0 string", context), runtime_error);
    BOOST_CHECK_THROW(CallRPC("listunspent 0 1 not_array", context), runtime_error);
    BOOST_CHECK_THROW(CallRPC("listunspent 0 1 [] extra", context), runtime_error);
    BOOST_CHECK_NO_THROW(r = CallRPC("listunspent 0 1 []", context));
    BOOST_CHECK(r.get_array().empty());

    /*********************************
     *      listreceivedbyaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress", context));
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress 0", context));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress not_int", context), runtime_error);
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress 0 not_bool", context), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress 0 true", context));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress 0 true extra", context), runtime_error);

    /*********************************
     *      listsinceblock
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listsinceblock", context));

    /*********************************
     *      listtransactions
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listtransactions", context));
    BOOST_CHECK_NO_THROW(CallRPC("listtransactions " + demoAddress.ToString(), context));
    BOOST_CHECK_NO_THROW(CallRPC("listtransactions " + demoAddress.ToString() + " 20", context));
    BOOST_CHECK_NO_THROW(CallRPC("listtransactions " + demoAddress.ToString() + " 20 0", context));
    BOOST_CHECK_THROW(CallRPC("listtransactions " + demoAddress.ToString() + " not_int", context), runtime_error);

    /*********************************
     *      listlockunspent
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listlockunspent", context));

    /*********************************
     *      listaddressgroupings
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listaddressgroupings", context));

    /*********************************
     *      getrawchangeaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getrawchangeaddress", context));

    /*********************************
     *      getnewaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getnewaddress", context));
    BOOST_CHECK_NO_THROW(CallRPC("getnewaddress getnewaddress_demoaccount", context));

    /*********************************
     *      signmessage + verifymessage
     *********************************/
    BOOST_CHECK_NO_THROW(retValue = CallRPC("signmessage " + demoAddress.ToString() + " mymessage", context));
    BOOST_CHECK_THROW(CallRPC("signmessage", context), runtime_error);
    /* Should throw error because this address is not loaded in the wallet */
    BOOST_CHECK_THROW(CallRPC("signmessage PwBcySALqBWYqf75g4YRUE7U1ymGvbuThA mymessage", context), runtime_error);

    /* missing arguments */
    BOOST_CHECK_THROW(CallRPC("verifymessage " + demoAddress.ToString(), context), runtime_error);
    BOOST_CHECK_THROW(CallRPC("verifymessage " + demoAddress.ToString() + " " + retValue.get_str(), context), runtime_error);
    /* Illegal address */
    BOOST_CHECK_THROW(CallRPC("verifymessage uWwyrg86LkihRv6sVmqqT1nSLCebSQXeH " + retValue.get_str() + " mymessage", context), runtime_error);
    /* wrong address */
    BOOST_CHECK(CallRPC("verifymessage PjwLze4moQRruqnTgjCFZjeDksanqzfeGS " + retValue.get_str() + " mymessage", context).get_bool() == false);
    /* Correct address and signature but wrong message */
    BOOST_CHECK(CallRPC("verifymessage " + demoAddress.ToString() + " " + retValue.get_str() + " wrongmessage", context).get_bool() == false);
    /* Correct address, message and signature*/
    BOOST_CHECK(CallRPC("verifymessage " + demoAddress.ToString() + " " + retValue.get_str() + " mymessage", context).get_bool() == true);


    /*********************************
     *      fundrawtransaction
     *********************************/
    BOOST_CHECK_THROW(CallRPC("fundrawtransaction 28z", context), runtime_error);
    BOOST_CHECK_THROW(CallRPC("fundrawtransaction 01000000000180969800000000001976a91450ce0a4b0ee0ddeb633da85199728b940ac3fe9488ac00000000", context), runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
