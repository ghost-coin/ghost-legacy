// Copyright (c) 2014-2016 The ShadowCoin developers
// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>

#include <algorithm>
#include <string>

#include <smsg/smessage.h>
#include <smsg/db.h>
#include <script/ismine.h>
#include <util/strencodings.h>
#include <core_io.h>
#include <base58.h>
#include <rpc/util.h>
#include <validation.h>
#include <fs.h>

#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif

#include <univalue.h>

static void EnsureSMSGIsEnabled()
{
    if (!smsg::fSecMsgEnabled)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Secure messaging is disabled.");
};

static UniValue smsgenable(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            RPCHelpMan{"smsgenable",
                "Enable secure messaging on the specified wallet.\n"
                "SMSG can only be enabled on one wallet.\n",
                {
                    {"walletname", RPCArg::Type::STR, /* default */ "wallet.dat", "Enable smsg on a specific wallet."},
                },
                RPCResults{},
                RPCExamples{""},
            }.ToString());

    if (smsg::fSecMsgEnabled) {
        throw JSONRPCError(RPC_MISC_ERROR, "Secure messaging is already enabled.");
    }

    UniValue result(UniValue::VOBJ);

    std::shared_ptr<CWallet> pwallet;
    std::string walletName = "none";
#ifdef ENABLE_WALLET
    auto vpwallets = GetWallets();

    if (!request.params[0].isNull()) {
        std::string sFindWallet = request.params[0].get_str();

        for (auto pw : vpwallets) {
            if (pw->GetName() != sFindWallet) {
                continue;
            }
            pwallet = pw;
            break;
        }
        if (!pwallet) {
            throw JSONRPCError(RPC_MISC_ERROR, "Wallet not found: \"" + sFindWallet + "\"");
        }
    } else {
        if (vpwallets.size() > 0) {
            pwallet = vpwallets[0];
        }
    }
    if (pwallet) {
        walletName = pwallet->GetName();
    }
#endif

    result.pushKV("result", (smsgModule.Enable(pwallet) ? "Enabled secure messaging." : "Failed to enable secure messaging."));
    result.pushKV("wallet", walletName);

    return result;
}

static UniValue smsgdisable(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            RPCHelpMan{"smsgdisable",
                "\nDisable secure messaging.\n",
                {
                },
                RPCResults{},
                RPCExamples{""},
            }.ToString());

    if (!smsg::fSecMsgEnabled)
        throw JSONRPCError(RPC_MISC_ERROR, "Secure messaging is already disabled.");

    UniValue result(UniValue::VOBJ);

    result.pushKV("result", (smsgModule.Disable() ? "Disabled secure messaging." : "Failed to disable secure messaging."));

    return result;
}

static UniValue smsgoptions(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            RPCHelpMan{"smsgoptions",
                "\nList and manage options.\n",
                {
                    {"list with_description|set \"optname\" \"value\"", RPCArg::Type::STR, /* default */ "list", "Command input."},
                },
                RPCResults{},
                RPCExamples{
            "\nList possible options with descriptions.\n"
            + HelpExampleCli("smsgoptions", "list 1")
                },
            }.ToString());

    std::string mode = "list";
    if (request.params.size() > 0) {
        mode = request.params[0].get_str();
    }

    UniValue result(UniValue::VOBJ);

    if (mode == "list") {
        UniValue options(UniValue::VARR);

        bool fDescriptions = false;
        if (!request.params[1].isNull()) {
            fDescriptions = GetBool(request.params[1]);
        }

        UniValue option(UniValue::VOBJ);
        option.pushKV("name", "newAddressRecv");
        option.pushKV("value", smsgModule.options.fNewAddressRecv);
        if (fDescriptions) {
            option.pushKV("description", "Enable receiving messages for newly created addresses.");
        }
        options.push_back(option);

        option = UniValue(UniValue::VOBJ);
        option.pushKV("name", "newAddressAnon");
        option.pushKV("value", smsgModule.options.fNewAddressAnon);
        if (fDescriptions) {
            option.pushKV("description", "Enable receiving anonymous messages for newly created addresses.");
        }
        options.push_back(option);

        option = UniValue(UniValue::VOBJ);
        option.pushKV("name", "scanIncoming");
        option.pushKV("value", smsgModule.options.fScanIncoming);
        if (fDescriptions) {
            option.pushKV("description", "Scan incoming blocks for public keys, -smsgscanincoming must also be set");
        }
        options.push_back(option);

        result.pushKV("options", options);
        result.pushKV("result", "Success.");
    } else
    if (mode == "set") {
        if (request.params.size() < 3) {
            result.pushKV("result", "Too few parameters.");
            result.pushKV("expected", "set <optname> <value>");
            return result;
        }

        std::string optname = request.params[1].get_str();
        bool fValue = GetBool(request.params[2]);

        std::transform(optname.begin(), optname.end(), optname.begin(), ::tolower);
        if (optname == "newaddressrecv") {
            smsgModule.options.fNewAddressRecv = fValue;
            result.pushKV("set option", std::string("newAddressRecv = ") + (smsgModule.options.fNewAddressRecv ? "true" : "false"));
        } else
        if (optname == "newaddressanon") {
            smsgModule.options.fNewAddressAnon = fValue;
            result.pushKV("set option", std::string("newAddressAnon = ") + (smsgModule.options.fNewAddressAnon ? "true" : "false"));
        } else
        if (optname == "scanincoming") {
            smsgModule.options.fScanIncoming = fValue;
            result.pushKV("set option", std::string("scanIncoming = ") + (smsgModule.options.fScanIncoming ? "true" : "false"));
        } else {
            result.pushKV("result", "Option not found.");
            return result;
        }
    } else {
        result.pushKV("result", "Unknown Mode.");
        result.pushKV("expected", "smsgoptions [list|set <optname> <value>]");
    }

    return result;
}

static UniValue smsglocalkeys(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            RPCHelpMan{"smsglocalkeys",
                "\nList and manage keys.\n",
                {
                    {"whitelist|all|wallet|recv +/- \"address\"|anon +/- \"address\"", RPCArg::Type::STR, /* default */ "whitelist", "Command input."},
                },
                RPCResults{},
                RPCExamples{""},
            }.ToString());

    EnsureSMSGIsEnabled();

    UniValue result(UniValue::VOBJ);

    std::string mode = "whitelist";
    if (request.params.size() > 0) {
        mode = request.params[0].get_str();
    }

    if (mode == "whitelist"
        || mode == "all") {
        LOCK(smsgModule.cs_smsg);
        uint32_t nKeys = 0;
        int all = mode == "all" ? 1 : 0;

        UniValue keys(UniValue::VARR);
#ifdef ENABLE_WALLET
        if (smsgModule.pwallet) {
            for (auto it = smsgModule.addresses.begin(); it != smsgModule.addresses.end(); ++it) {
                if (!all
                    && !it->fReceiveEnabled) {
                    continue;
                }

                CKeyID &keyID = it->address;
                std::string sPublicKey;
                CPubKey pubKey;

                if (smsgModule.pwallet) {
                    if (!smsgModule.pwallet->GetPubKey(keyID, pubKey)) {
                        continue;
                    }
                    if (!pubKey.IsValid()
                        || !pubKey.IsCompressed()) {
                        continue;
                    }
                    sPublicKey = EncodeBase58(pubKey.begin(), pubKey.end());
                }

                UniValue objM(UniValue::VOBJ);
                std::string sInfo, sLabel;
                {
                    LOCK(smsgModule.pwallet->cs_wallet);
                    sLabel = smsgModule.pwallet->mapAddressBook[PKHash(keyID)].name;
                }
                if (all) {
                    sInfo = std::string("Receive ") + (it->fReceiveEnabled ? "on,  " : "off, ");
                }
                sInfo += std::string("Anon ") + (it->fReceiveAnon ? "on" : "off");
                //result.pushKV("key", it->sAddress + " - " + sPublicKey + " " + sInfo + " - " + sLabel);
                objM.pushKV("address", EncodeDestination(PKHash(keyID)));
                objM.pushKV("public_key", sPublicKey);
                objM.pushKV("receive", (it->fReceiveEnabled ? "1" : "0"));
                objM.pushKV("anon", (it->fReceiveAnon ? "1" : "0"));
                objM.pushKV("label", sLabel);
                keys.push_back(objM);

                nKeys++;
            }
            result.pushKV("wallet_keys", keys);
        }
#endif

        keys = UniValue(UniValue::VARR);
        for (auto &p : smsgModule.keyStore.mapKeys) {
            auto &key = p.second;
            UniValue objM(UniValue::VOBJ);
            CPubKey pk = key.key.GetPubKey();
            objM.pushKV("address", EncodeDestination(PKHash(p.first)));
            objM.pushKV("public_key", EncodeBase58(pk.begin(), pk.end()));
            objM.pushKV("receive", (key.nFlags & smsg::SMK_RECEIVE_ON ? "1" : "0"));
            objM.pushKV("anon", (key.nFlags & smsg::SMK_RECEIVE_ANON ? "1" : "0"));
            objM.pushKV("label", key.sLabel);
            keys.push_back(objM);

            nKeys++;
        }
        result.pushKV("smsg_keys", keys);

        result.pushKV("result", strprintf("%u", nKeys));
    } else
    if (mode == "recv") {
        if (request.params.size() < 3) {
            result.pushKV("result", "Too few parameters.");
            result.pushKV("expected", "recv <+/-> <address>");
            return result;
        }

        bool fValue = GetBool(request.params[1]);
        std::string addr = request.params[2].get_str();

        CKeyID keyID;
        CBitcoinAddress coinAddress(addr);
        if (!coinAddress.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address.");
        }
        if (!coinAddress.GetKeyID(keyID)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address.");
        }

        if (!smsgModule.SetWalletAddressOption(keyID, "receive", fValue)
            && !smsgModule.SetSmsgAddressOption(keyID, "receive", fValue)) {
            result.pushKV("result", "Address not found.");
            return result;
        }

        std::string sInfo;
        sInfo = std::string("Receive ") + (fValue ? "on" : "off");
        result.pushKV("result", "Success.");
        result.pushKV("key", coinAddress.ToString() + " " + sInfo);
        return result;
    } else
    if (mode == "anon") {
        if (request.params.size() < 3) {
            result.pushKV("result", "Too few parameters.");
            result.pushKV("expected", "anon <+/-> <address>");
            return result;
        }

        bool fValue = GetBool(request.params[1]);
        std::string addr = request.params[2].get_str();

        CKeyID keyID;
        CBitcoinAddress coinAddress(addr);
        if (!coinAddress.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address.");
        }
        if (!coinAddress.GetKeyID(keyID)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address.");
        }

        if (!smsgModule.SetWalletAddressOption(keyID, "anon", fValue)
            && !smsgModule.SetSmsgAddressOption(keyID, "anon", fValue)) {
            result.pushKV("result", "Address not found.");
            return result;
        }

        std::string sInfo;
        sInfo += std::string("Anon ") + (fValue ? "on" : "off");
        result.pushKV("result", "Success.");
        result.pushKV("key", coinAddress.ToString() + " " + sInfo);

        return result;
    } else
    if (mode == "wallet") {
#ifdef ENABLE_WALLET
        if (!smsgModule.pwallet) {
            throw JSONRPCError(RPC_MISC_ERROR, "No wallet.");
        }
        LOCK(smsgModule.pwallet->cs_wallet);
        uint32_t nKeys = 0;
        UniValue keys(UniValue::VOBJ);

        for (const auto &entry : smsgModule.pwallet->mapAddressBook) {
            if (!IsMine(*smsgModule.pwallet, entry.first)) {
                continue;
            }

            CBitcoinAddress coinAddress(entry.first);
            if (!coinAddress.IsValid()) {
                continue;
            }

            std::string address = coinAddress.ToString();
            std::string sPublicKey;

            CKeyID keyID;
            if (!coinAddress.GetKeyID(keyID)) {
                continue;
            }

            CPubKey pubKey;
            if (!smsgModule.pwallet->GetPubKey(keyID, pubKey)) {
                continue;
            }
            if (!pubKey.IsValid()
                || !pubKey.IsCompressed()) {
                continue;
            }

            sPublicKey = EncodeBase58(pubKey.begin(), pubKey.end());
            UniValue objM(UniValue::VOBJ);

            objM.pushKV("key", address);
            objM.pushKV("publickey", sPublicKey);
            objM.pushKV("label", entry.second.name);

            keys.push_back(objM);
            nKeys++;
        }
        result.pushKV("keys", keys);
        result.pushKV("result", strprintf("%u", nKeys));
#else
        throw JSONRPCError(RPC_MISC_ERROR, "No wallet.");
#endif
    } else {
        result.pushKV("result", "Unknown Mode.");
        result.pushKV("expected", "smsglocalkeys [whitelist|all|wallet|recv <+/-> <address>|anon <+/-> <address>]");
    }

    return result;
};

static UniValue smsgscanchain(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            RPCHelpMan{"smsgscanchain",
                "\nLook for public keys in the block chain.\n",
                {},
                RPCResults{},
                RPCExamples{""},
            }.ToString());

    EnsureSMSGIsEnabled();

    UniValue result(UniValue::VOBJ);
    if (!smsgModule.ScanBlockChain()) {
        result.pushKV("result", "Scan Chain Failed.");
    } else {
        result.pushKV("result", "Scan Chain Completed.");
    }

    return result;
}

static UniValue smsgscanbuckets(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            RPCHelpMan{"smsgscanbuckets",
                "\nForce rescan of all messages in the bucket store.\n"
                "Wallet must be unlocked if any receiving keys are stored in the wallet.\n",
                {},
                RPCResults{},
                RPCExamples{""},
            }.ToString());

    EnsureSMSGIsEnabled();

#ifdef ENABLE_WALLET
    if (smsgModule.pwallet && smsgModule.pwallet->IsLocked()
        && smsgModule.addresses.size() > 0) {
        throw JSONRPCError(RPC_MISC_ERROR, "Wallet is locked.");
    }
#endif

    UniValue result(UniValue::VOBJ);
    if (!smsgModule.ScanBuckets()) {
        result.pushKV("result", "Scan Buckets Failed.");
    } else {
        result.pushKV("result", "Scan Buckets Completed.");
    }

    return result;
}

static UniValue smsgaddaddress(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            RPCHelpMan{"smsgaddaddress",
                "\nAdd address and matching public key to database.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Address to add."},
                    {"pubkey", RPCArg::Type::STR, RPCArg::Optional::NO, "Public key for \"address\"."},
                },
                RPCResults{},
                RPCExamples{""},
            }.ToString());

    EnsureSMSGIsEnabled();

    std::string addr = request.params[0].get_str();
    std::string pubk = request.params[1].get_str();

    UniValue result(UniValue::VOBJ);
    int rv = smsgModule.AddAddress(addr, pubk);
    if (rv != 0) {
        result.pushKV("result", "Public key not added to db.");
        result.pushKV("reason", smsg::GetString(rv));
    } else {
        result.pushKV("result", "Public key added to db.");
    }

    return result;
}

static UniValue smsgaddlocaladdress(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            RPCHelpMan{"smsgaddlocaladdress",
                "\nEnable receiving messages on <address>.\n"
                "Key for \"address\" must exist in the wallet.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Address to add."},
                },
                RPCResults{},
                RPCExamples{""},
            }.ToString());

    EnsureSMSGIsEnabled();

    std::string addr = request.params[0].get_str();

    UniValue result(UniValue::VOBJ);
    int rv = smsgModule.AddLocalAddress(addr);
    if (rv != 0) {
        result.pushKV("result", "Address not added.");
        result.pushKV("reason", smsg::GetString(rv));
    } else {
        result.pushKV("result", "Receiving messages enabled for address.");
    }

    return result;
}

static UniValue smsgimportprivkey(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            RPCHelpMan{"smsgimportprivkey",
                "\nAdds a private key (as returned by dumpprivkey) to the smsg database.\n"
                "The imported key can receive messages even if the wallet is locked.\n",
                {
                    {"privkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The private key to import (see dumpprivkey)."},
                    {"label", RPCArg::Type::STR, /* default */ "", "An optional label."},
                },
                RPCResults{},
                RPCExamples{
            "\nDump a private key\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"") +
            "\nImport the private key\n"
            + HelpExampleCli("smsgimportprivkey", "\"mykey\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("smsgimportprivkey", "\"mykey\", \"testing\"")
                },
            }.ToString());

    EnsureSMSGIsEnabled();

    CBitcoinSecret vchSecret;
    if (!request.params[0].isStr()
        || !vchSecret.SetString(request.params[0].get_str())) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");
    }

    std::string strLabel = "";
    if (!request.params[1].isNull()) {
        strLabel = request.params[1].get_str();
    }

    int rv = smsgModule.ImportPrivkey(vchSecret, strLabel);
    if (0 != rv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Import failed.");
    }

    return NullUniValue;
}

static UniValue smsggetpubkey(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            RPCHelpMan{"smsggetpubkey",
                "\nReturn the base58 encoded compressed public key for an address.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Return the pubkey matching \"address\"."},
                },
                RPCResult{
            "{\n"
            "  \"address\": \"...\"             (string) address of public key\n"
            "  \"publickey\": \"...\"           (string) public key of address\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("smsggetpubkey", "\"myaddress\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("smsggetpubkey", "\"myaddress\"")
                },
            }.ToString());

    EnsureSMSGIsEnabled();

    std::string address = request.params[0].get_str();
    std::string publicKey;

    UniValue result(UniValue::VOBJ);
    int rv = smsgModule.GetLocalPublicKey(address, publicKey);
    switch (rv) {
        case smsg::SMSG_NO_ERROR:
            result.pushKV("address", address);
            result.pushKV("publickey", publicKey);
            return result; // success, don't check db
        case smsg::SMSG_WALLET_NO_PUBKEY:
            break; // check db
        //case 1:
        default:
            throw JSONRPCError(RPC_INTERNAL_ERROR, smsg::GetString(rv));
    }

    CBitcoinAddress coinAddress(address);
    CKeyID keyID;
    if (!coinAddress.GetKeyID(keyID)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid address.");
    }

    CPubKey cpkFromDB;
    rv = smsgModule.GetStoredKey(keyID, cpkFromDB);

    switch (rv) {
        case smsg::SMSG_NO_ERROR:
            if (!cpkFromDB.IsValid()
                || !cpkFromDB.IsCompressed()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Invalid public key.");
            } else {
                publicKey = EncodeBase58(cpkFromDB.begin(), cpkFromDB.end());

                result.pushKV("address", address);
                result.pushKV("publickey", publicKey);
            }
            break;
        case smsg::SMSG_PUBKEY_NOT_EXISTS:
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Address not found in wallet or db.");
        default:
            throw JSONRPCError(RPC_INTERNAL_ERROR, smsg::GetString(rv));
    }

    return result;
}

static UniValue smsgsend(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 10)
        throw std::runtime_error(
            RPCHelpMan{"smsgsend",
                "\nSend an encrypted message from \"address_from\" to \"address_to\".\n",
                {
                    {"address_from", RPCArg::Type::STR, RPCArg::Optional::NO, "The address of the sender."},
                    {"address_to", RPCArg::Type::STR, RPCArg::Optional::NO, "The address of the recipient."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to send."},
                    {"paid_msg", RPCArg::Type::BOOL, /* default */ "false", "Send as paid message."},
                    {"days_retention", RPCArg::Type::NUM, /* default */ "1", "No. of days for which paid message will be retained by network."},
                    {"testfee", RPCArg::Type::BOOL, /* default */ "false", "Don't send the message, only estimate the fee."},
                    {"fromfile", RPCArg::Type::BOOL, /* default */ "false", "Send file as message, path specified in \"message\"."},
                    {"decodehex", RPCArg::Type::BOOL, /* default */ "false", "Decode \"message\" from hex before sending."},
                    {"submitmsg", RPCArg::Type::BOOL, /* default */ "true", "Submit smsg to network, if false POW is not set and hex encoded smsg returned."},
                    {"savemsg", RPCArg::Type::BOOL, /* default */ "true", "Save smsg to outbox."},
                },
                RPCResult{
            "{\n"
            "  \"result\": \"Sent\"/\"Not Sent\"       (string) address of public key\n"
            "  \"msgid\": \"...\"                    (string) if sent, a message identifier\n"
            "  \"txid\": \"...\"                     (string) if paid_msg the txnid of the funding txn\n"
            "  \"fee\": n                          (amount) if paid_msg the fee paid\n"
            "}\n"
                },
                RPCExamples{
             HelpExampleCli("smsgsend", "\"myaddress\" \"toaddress\" \"message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("smsgsend", "\"myaddress\", \"toaddress\", \"message\"")
                },
            }.ToString());

    EnsureSMSGIsEnabled();

    RPCTypeCheck(request.params,
        {UniValue::VSTR, UniValue::VSTR, UniValue::VSTR,
         UniValue::VBOOL, UniValue::VNUM, UniValue::VBOOL}, true);

    std::string addrFrom  = request.params[0].get_str();
    std::string addrTo    = request.params[1].get_str();
    std::string msg       = request.params[2].get_str();

    bool fPaid = request.params[3].isNull() ? false : request.params[3].get_bool();
    int nRetention = request.params[4].isNull() ? 1 : request.params[4].get_int();
    bool fTestFee = request.params[5].isNull() ? false : request.params[5].get_bool();
    bool fFromFile = request.params[6].isNull() ? false : request.params[6].get_bool();
    bool fDecodeHex = request.params[7].isNull() ? false : request.params[7].get_bool();
    bool submit_msg = request.params[8].isNull() ? true : request.params[8].get_bool();
    bool save_msg = request.params[9].isNull() ? true : request.params[9].get_bool();

    if (fFromFile && fDecodeHex) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Can't use decodehex with fromfile.");
    }

    if (fDecodeHex) {
        if (!IsHex(msg)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Expect hex encoded message with decodehex.");
        }
        std::vector<uint8_t> vData = ParseHex(msg);
        msg = std::string(vData.begin(), vData.end());
    }

    CAmount nFee;

    if (fPaid && Params().GetConsensus().nPaidSmsgTime > GetTime()) {
        throw std::runtime_error("Paid SMSG not yet active on mainnet.");
    }

    CKeyID kiFrom, kiTo;
    CBitcoinAddress coinAddress(addrFrom);
    if (!coinAddress.IsValid() || !coinAddress.GetKeyID(kiFrom)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid from address.");
    }
    coinAddress.SetString(addrTo);
    if (!coinAddress.IsValid() || !coinAddress.GetKeyID(kiTo)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid to address.");
    }


    UniValue result(UniValue::VOBJ);
    std::string sError;
    smsg::SecureMessage smsgOut;
    if (smsgModule.Send(kiFrom, kiTo, msg, smsgOut, sError, fPaid, nRetention, fTestFee, &nFee, fFromFile, submit_msg, save_msg) != 0) {
        result.pushKV("result", "Send failed.");
        result.pushKV("error", sError);
    } else {
        result.pushKV("result", (!submit_msg || fTestFee) ? "Not Sent." : "Sent.");

        if (!fTestFee) {
            result.pushKV("msgid", HexStr(smsgModule.GetMsgID(smsgOut)));
        }

        if (!submit_msg) {
            result.pushKV("msg", HexStr(smsgOut.data(), smsgOut.data() + smsg::SMSG_HDR_LEN) +
                                 HexStr(smsgOut.pPayload, smsgOut.pPayload + smsgOut.nPayload));
        }

        if (fPaid) {
            if (!fTestFee) {
                uint256 txid;
                smsgOut.GetFundingTxid(txid);
                result.pushKV("txid", txid.ToString());
            }
            result.pushKV("fee", ValueFromAmount(nFee));
        }
    }

    return result;
}

static UniValue smsgsendanon(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            RPCHelpMan{"smsgsendanon",
                "\nDEPRECATED. Send an anonymous encrypted message to addrTo.\n",
                {
                    {"address_to", RPCArg::Type::STR, RPCArg::Optional::NO, "Address to send to."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "Message to send."},
                },
                RPCResults{},
                RPCExamples{""},
            }.ToString());

    EnsureSMSGIsEnabled();

    std::string addrTo    = request.params[0].get_str();
    std::string msg       = request.params[1].get_str();

    CKeyID kiFrom, kiTo;
    CBitcoinAddress coinAddress(addrTo);
    if (!coinAddress.IsValid() || !coinAddress.GetKeyID(kiTo)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid to address.");
    }

    UniValue result(UniValue::VOBJ);
    std::string sError;
    smsg::SecureMessage smsgOut;
    if (smsgModule.Send(kiFrom, kiTo, msg, smsgOut, sError) != 0) {
        result.pushKV("result", "Send failed.");
        result.pushKV("error", sError);
    } else {
        result.pushKV("msgid", HexStr(smsgModule.GetMsgID(smsgOut)));
        result.pushKV("result", "Sent.");
    }

    return result;
}

static UniValue smsginbox(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            RPCHelpMan{"smsginbox",
                "\nDecrypt and display received messages.\n"
                "Warning: clear will delete all messages.\n",
                {
                    {"mode", RPCArg::Type::STR, /* default */ "unread", "\"all|unread|clear\" List all messages, unread messages or clear all messages."},
                    {"filter", RPCArg::Type::STR, /* default */ "", "Filter messages when in list mode. Applied to from, to and text fields."},
                    {"options", RPCArg::Type::OBJ, /* default */ "", "",
                        {
                            {"updatestatus", RPCArg::Type::BOOL, /* default */ "true", "Update read status if true."},
                            {"encoding", RPCArg::Type::STR, /* default */ "text", "Display message data in encoding, values: \"text\", \"hex\", \"none\"."},
                        },
                        "options"},
                },
                RPCResult{
            "{\n"
            "  \"msgid\": \"str\"                    (string) The message identifier\n"
            "  \"version\": \"str\"                  (string) The message version\n"
            "  \"received\": \"time\"                (string) Time the message was received\n"
            "  \"sent\": \"time\"                    (string) Time the message was sent\n"
            "  \"daysretention\": int              (int) Number of days message will stay in the network for\n"
            "  \"from\": \"str\"                     (string) Address the message was sent from\n"
            "  \"to\": \"str\"                       (string) Address the message was sent to\n"
            "  \"text\": \"str\"                     (string) Message text\n"
            "}\n"
                },
                RPCExamples{""},
            }.ToString());

    EnsureSMSGIsEnabled();

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR, UniValue::VOBJ}, true);

    std::string mode = request.params[0].isStr() ? request.params[0].get_str() : "unread";
    std::string filter = request.params[1].isStr() ? request.params[1].get_str() : "";

    std::string sEnc = "text";
    bool update_status = true;
    if (request.params[2].isObject()) {
        UniValue options = request.params[2].get_obj();
        if (options["updatestatus"].isBool()) {
            update_status = options["updatestatus"].get_bool();
        }
        if (options["encoding"].isStr()) {
            sEnc = options["encoding"].get_str();
        }
    }

    UniValue result(UniValue::VOBJ);

    {
        LOCK(smsg::cs_smsgDB);

        smsg::SecMsgDB dbInbox;
        if (!dbInbox.Open("cr+")) {
            throw std::runtime_error("Could not open DB.");
        }

        uint32_t nMessages = 0;
        std::string sPrefix("im");
        uint8_t chKey[30];

        if (mode == "clear") {
            dbInbox.TxnBegin();

            leveldb::Iterator *it = dbInbox.pdb->NewIterator(leveldb::ReadOptions());
            while (dbInbox.NextSmesgKey(it, sPrefix, chKey)) {
                dbInbox.EraseSmesg(chKey);
                nMessages++;
            }
            delete it;
            dbInbox.TxnCommit();

            result.pushKV("result", strprintf("Deleted %u messages.", nMessages));
        } else
        if (mode == "all"
            || mode == "unread") {
            int fCheckReadStatus = mode == "unread" ? 1 : 0;

            smsg::SecMsgStored smsgStored;
            smsg::MessageData msg;

            dbInbox.TxnBegin();

            leveldb::Iterator *it = dbInbox.pdb->NewIterator(leveldb::ReadOptions());
            UniValue messageList(UniValue::VARR);

            while (dbInbox.NextSmesg(it, sPrefix, chKey, smsgStored)) {
                if (fCheckReadStatus
                    && !(smsgStored.status & SMSG_MASK_UNREAD)) {
                    continue;
                }
                uint8_t *pHeader = &smsgStored.vchMessage[0];
                const smsg::SecureMessage *psmsg = (smsg::SecureMessage*) pHeader;

                UniValue objM(UniValue::VOBJ);
                objM.pushKV("msgid", HexStr(&chKey[2], &chKey[2] + 28)); // timestamp+hash
                objM.pushKV("version", strprintf("%02x%02x", psmsg->version[0], psmsg->version[1]));

                uint32_t nPayload = smsgStored.vchMessage.size() - smsg::SMSG_HDR_LEN;
                int rv = smsgModule.Decrypt(false, smsgStored.addrTo, pHeader, pHeader + smsg::SMSG_HDR_LEN, nPayload, msg);
                if (rv == 0) {
                    std::string sAddrTo = EncodeDestination(PKHash(smsgStored.addrTo));
                    std::string sText = std::string((char*)msg.vchMessage.data());
                    if (filter.size() > 0
                        && !(part::stringsMatchI(msg.sFromAddress, filter, 3) ||
                            part::stringsMatchI(sAddrTo, filter, 3) ||
                            part::stringsMatchI(sText, filter, 3))) {
                        continue;
                    }

                    PushTime(objM, "received", smsgStored.timeReceived);
                    PushTime(objM, "sent", msg.timestamp);
                    objM.pushKV("paid", UniValue(psmsg->IsPaidVersion()));

                    uint32_t nDaysRetention = psmsg->IsPaidVersion() ? psmsg->nonce[0] : 2;
                    int64_t ttl = smsg::SMSGGetSecondsInDay() * nDaysRetention;
                    objM.pushKV("daysretention", (int)nDaysRetention);
                    PushTime(objM, "expiration", psmsg->timestamp + ttl);

                    uint32_t nPayload = smsgStored.vchMessage.size() - smsg::SMSG_HDR_LEN;
                    objM.pushKV("payloadsize", (int)nPayload);

                    objM.pushKV("from", msg.sFromAddress);
                    objM.pushKV("to", sAddrTo);
                    if (sEnc == "none") {
                    } else
                    if (sEnc == "text") {
                        objM.pushKV("text", sText);
                    } else
                    if (sEnc == "hex") {
                        objM.pushKV("hex", HexStr(sText));
                    } else {
                        objM.pushKV("unknown_encoding", sEnc);
                    }
                } else {
                    if (filter.size() > 0) {
                        continue;
                    }

                    objM.pushKV("status", "Decrypt failed");
                    objM.pushKV("error", smsg::GetString(rv));
                }

                messageList.push_back(objM);

                // Only set 'read' status if the message decrypted successfully and update_status is set
                if (fCheckReadStatus && rv == 0 && update_status) {
                    smsgStored.status &= ~SMSG_MASK_UNREAD;
                    dbInbox.WriteSmesg(chKey, smsgStored);
                }
                nMessages++;
            }
            delete it;
            dbInbox.TxnCommit();

            result.pushKV("messages", messageList);
            result.pushKV("result", strprintf("%u", nMessages));
        } else {
            result.pushKV("result", "Unknown Mode.");
            result.pushKV("expected", "all|unread|clear.");
        }
    } // cs_smsgDB

    return result;
};

static UniValue smsgoutbox(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            RPCHelpMan{"smsgoutbox",
                "\nDecrypt and display all sent messages.\n"
                "Warning: \"mode\"=\"clear\" will delete all sent messages.\n",
                {
                    {"mode", RPCArg::Type::STR, /* default */ "all", "all|clear, List or clear messages."},
                    {"filter", RPCArg::Type::STR, /* default */ "", "Filter messages when in list mode. Applied to from, to and text fields."},
                    {"options", RPCArg::Type::OBJ, /* default */ "", "",
                        {
                            {"encoding", RPCArg::Type::STR, /* default */ "text", "Display message data in encoding, values: \"text\", \"hex\", \"none\"."},
                        },
                        "options"},
                },
                RPCResult{
            "{\n"
            "  \"msgid\": \"str\"                    (string) The message identifier\n"
            "  \"version\": \"str\"                  (string) The message version\n"
            "  \"sent\": \"time\"                    (string) Time the message was sent\n"
            "  \"from\": \"str\"                     (string) Address the message was sent from\n"
            "  \"to\": \"str\"                       (string) Address the message was sent to\n"
            "  \"text\": \"str\"                     (string) Message text\n"
            "}\n"
                },
                RPCExamples{""},
            }.ToString());

    EnsureSMSGIsEnabled();

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR}, true);

    std::string mode = request.params[0].isStr() ? request.params[0].get_str() : "all";
    std::string filter = request.params[1].isStr() ? request.params[1].get_str() : "";

    std::string sEnc = "text";
    if (request.params[2].isObject()) {
        UniValue options = request.params[2].get_obj();
        if (options["encoding"].isStr()) {
            sEnc = options["encoding"].get_str();
        }
    }

    UniValue result(UniValue::VOBJ);

    std::string sPrefix("sm");
    uint8_t chKey[30];
    memset(&chKey[0], 0, sizeof(chKey));

    {
        LOCK(smsg::cs_smsgDB);

        smsg::SecMsgDB dbOutbox;
        if (!dbOutbox.Open("cr+")) {
            throw std::runtime_error("Could not open DB.");
        }

        uint32_t nMessages = 0;

        if (mode == "clear") {
            dbOutbox.TxnBegin();

            leveldb::Iterator *it = dbOutbox.pdb->NewIterator(leveldb::ReadOptions());
            while (dbOutbox.NextSmesgKey(it, sPrefix, chKey)) {
                dbOutbox.EraseSmesg(chKey);
                nMessages++;
            }
            delete it;
            dbOutbox.TxnCommit();

            result.pushKV("result", strprintf("Deleted %u messages.", nMessages));
        } else
        if (mode == "all") {
            smsg::SecMsgStored smsgStored;
            smsg::MessageData msg;
            leveldb::Iterator *it = dbOutbox.pdb->NewIterator(leveldb::ReadOptions());

            UniValue messageList(UniValue::VARR);

            while (dbOutbox.NextSmesg(it, sPrefix, chKey, smsgStored)) {
                uint8_t *pHeader = &smsgStored.vchMessage[0];
                const smsg::SecureMessage *psmsg = (smsg::SecureMessage*) pHeader;

                UniValue objM(UniValue::VOBJ);
                objM.pushKV("msgid", HexStr(&chKey[2], &chKey[2] + 28)); // timestamp+hash
                objM.pushKV("version", strprintf("%02x%02x", psmsg->version[0], psmsg->version[1]));

                uint32_t nPayload = smsgStored.vchMessage.size() - smsg::SMSG_HDR_LEN;
                int rv = smsgModule.Decrypt(false, smsgStored.addrOutbox, pHeader, pHeader + smsg::SMSG_HDR_LEN, nPayload, msg);
                if (rv == 0) {
                    std::string sAddrTo = EncodeDestination(PKHash(smsgStored.addrTo));
                    std::string sText = std::string((char*)msg.vchMessage.data());
                    if (filter.size() > 0
                        && !(part::stringsMatchI(msg.sFromAddress, filter, 3) ||
                            part::stringsMatchI(sAddrTo, filter, 3) ||
                            part::stringsMatchI(sText, filter, 3))) {
                        continue;
                    }

                    PushTime(objM, "sent", msg.timestamp);
                    objM.pushKV("paid", UniValue(psmsg->IsPaidVersion()));

                    uint32_t nDaysRetention = psmsg->IsPaidVersion() ? psmsg->nonce[0] : 2;
                    int64_t ttl = smsg::SMSGGetSecondsInDay() * nDaysRetention;
                    objM.pushKV("daysretention", (int)nDaysRetention);
                    PushTime(objM, "expiration", psmsg->timestamp + ttl);

                    uint32_t nPayload = smsgStored.vchMessage.size() - smsg::SMSG_HDR_LEN;
                    objM.pushKV("payloadsize", (int)nPayload);

                    objM.pushKV("from", msg.sFromAddress);
                    objM.pushKV("to", sAddrTo);
                    if (sEnc == "none") {
                    } else
                    if (sEnc == "text") {
                        objM.pushKV("text", sText);
                    } else
                    if (sEnc == "hex") {
                        objM.pushKV("hex", HexStr(sText));
                    } else {
                        objM.pushKV("unknown_encoding", sEnc);
                    }
                } else {
                    if (filter.size() > 0) {
                        continue;
                    }

                    objM.pushKV("status", "Decrypt failed");
                    objM.pushKV("error", smsg::GetString(rv));
                }
                messageList.push_back(objM);
                nMessages++;
            }
            delete it;

            result.pushKV("messages" ,messageList);
            result.pushKV("result", strprintf("%u", nMessages));
        } else {
            result.pushKV("result", "Unknown Mode.");
            result.pushKV("expected", "all|clear.");
        }
    }

    return result;
};


static UniValue smsgbuckets(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            RPCHelpMan{"smsgbuckets",
                "\nDisplay some statistics.\n",
                {
                    {"mode", RPCArg::Type::STR, /* default */ "stats", "stats|total|dump. \"dump\" will remove all buckets."},
                },
                RPCResults{},
                RPCExamples{""},
            }.ToString());

    EnsureSMSGIsEnabled();

    std::string mode = "stats";
    if (request.params.size() > 0) {
        mode = request.params[0].get_str();
    }

    UniValue result(UniValue::VOBJ);
    UniValue arrBuckets(UniValue::VARR);

    char cbuf[256];
    if (mode == "stats" || mode == "total") {
        bool show_buckets = mode != "total" ? true : false;
        uint32_t nBuckets = 0;
        uint32_t nMessages = 0;
        uint64_t nBytes = 0;
        {
            LOCK(smsgModule.cs_smsg);
            std::map<int64_t, smsg::SecMsgBucket>::const_iterator it;
            it = smsgModule.buckets.begin();

            for (it = smsgModule.buckets.begin(); it != smsgModule.buckets.end(); ++it) {
                const std::set<smsg::SecMsgToken> &tokenSet = it->second.setTokens;

                std::string sBucket = std::to_string(it->first);
                std::string sFile = sBucket + "_01.dat";
                std::string sHash = std::to_string(it->second.hash);

                size_t nActiveMessages = it->second.CountActive();

                nBuckets++;
                nMessages += nActiveMessages;

                UniValue objM(UniValue::VOBJ);
                if (show_buckets) {
                    objM.pushKV("bucket", sBucket);
                    PushTime(objM, "time", it->first);
                    objM.pushKV("no. messages", strprintf("%u", tokenSet.size()));
                    objM.pushKV("active messages", strprintf("%u", nActiveMessages));
                    objM.pushKV("hash", sHash);
                    objM.pushKV("last changed", part::GetTimeString(it->second.timeChanged, cbuf, sizeof(cbuf)));
                }

                fs::path fullPath = GetDataDir() / "smsgstore" / sFile;
                if (!fs::exists(fullPath)) {
                    if (tokenSet.size() == 0) {
                        objM.pushKV("file size", "Empty bucket.");
                    } else {
                        objM.pushKV("file size, error", "File not found.");
                    }
                } else {
                    try {
                        uint64_t nFBytes = 0;
                        nFBytes = fs::file_size(fullPath);
                        nBytes += nFBytes;
                        if (show_buckets) {
                            objM.pushKV("file size", part::BytesReadable(nFBytes));
                        }
                    } catch (const fs::filesystem_error& ex) {
                        objM.pushKV("file size, error", ex.what());
                    }
                }
                if (objM.size() > 0) {
                    arrBuckets.push_back(objM);
                }
            }
        } // cs_smsg

        UniValue objM(UniValue::VOBJ);
        objM.pushKV("numbuckets", (int)nBuckets);
        objM.pushKV("numpurged", (int)smsgModule.setPurged.size());
        objM.pushKV("messages", (int)nMessages);
        objM.pushKV("size", part::BytesReadable(nBytes));
        if (arrBuckets.size() > 0) {
            result.pushKV("buckets", arrBuckets);
        }
        result.pushKV("total", objM);
    } else
    if (mode == "dump") {
        {
            LOCK(smsgModule.cs_smsg);
            std::map<int64_t, smsg::SecMsgBucket>::iterator it;
            it = smsgModule.buckets.begin();

            for (it = smsgModule.buckets.begin(); it != smsgModule.buckets.end(); ++it) {
                std::string sFile = std::to_string(it->first) + "_01.dat";

                try {
                    fs::path fullPath = GetDataDir() / "smsgstore" / sFile;
                    fs::remove(fullPath);
                } catch (const fs::filesystem_error& ex) {
                    //objM.push_back(Pair("file size, error", ex.what()));
                    LogPrintf("Error removing bucket file %s.\n", ex.what());
                }
            }
            smsgModule.buckets.clear();
            smsgModule.start_time = GetAdjustedTime();
        } // cs_smsg

        result.pushKV("result", "Removed all buckets.");
    } else {
        result.pushKV("result", "Unknown Mode.");
        result.pushKV("expected", "stats|total|dump.");
    }

    return result;
};

static bool sortMsgAsc(const std::pair<int64_t, UniValue> &a, const std::pair<int64_t, UniValue> &b)
{
    return a.first < b.first;
};

static bool sortMsgDesc(const std::pair<int64_t, UniValue> &a, const std::pair<int64_t, UniValue> &b)
{
    return a.first > b.first;
};

static UniValue smsgview(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() > 6)
        throw std::runtime_error(
            RPCHelpMan{"smsgview",
                "\nView messages by address.\n"
                "Setting address to '*' will match all addresses\n"
                "'abc*' will match addresses with labels beginning 'abc'\n"
                "'*abc' will match addresses with labels ending 'abc'\n"
                "Full date/time format for from and to is yyyy-mm-ddThh:mm:ss\n"
                "From and to will accept incomplete inputs like: -from 2016\n",
                {
                    {"address/label", RPCArg::Type::STR, /* default */ "", ""},
                    {"asc/desc", RPCArg::Type::STR, /* default */ "", ""},
                    {"-from yyyy-mm-dd", RPCArg::Type::STR, /* default */ "", ""},
                    {"-to yyyy-mm-dd", RPCArg::Type::STR, /* default */ "", ""},
                },
                RPCResults{},
                RPCExamples{""},
            }.ToString());

    EnsureSMSGIsEnabled();

#ifdef ENABLE_WALLET
    if (smsgModule.pwallet->IsLocked()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Wallet is locked.");
    }

    char cbuf[256];
    bool fMatchAll = false;
    bool fDesc = false;
    int64_t tFrom = 0, tTo = 0;
    std::vector<CKeyID> vMatchAddress;
    std::string sTemp;

    if (request.params.size() > 0) {
        sTemp = request.params[0].get_str();

        // Blank address or "*" will match all
        if (sTemp.length() < 1) { // Error instead?
            fMatchAll = true;
        } else
        if (sTemp.length() == 1 && sTemp[0] == '*') {
            fMatchAll = true;
        }

        if (!fMatchAll) {
            CBitcoinAddress checkValid(sTemp);

            if (checkValid.IsValid()) {
                CKeyID ki;
                checkValid.GetKeyID(ki);
                vMatchAddress.push_back(ki);
            } else {
                // Lookup address by label, can match multiple addresses

                // TODO: Use Boost.Regex?
                int matchType = 0; // 0 full match, 1 startswith, 2 endswith
                if (sTemp[0] == '*') {
                    matchType = 1;
                    sTemp.erase(0, 1);
                } else
                if (sTemp[sTemp.length()-1] == '*') {
                    matchType = 2;
                    sTemp.erase(sTemp.length()-1, 1);
                }

                std::map<CTxDestination, CAddressBookData>::iterator itl;

                {
                    LOCK(smsgModule.pwallet->cs_wallet);
                    for (itl = smsgModule.pwallet->mapAddressBook.begin(); itl != smsgModule.pwallet->mapAddressBook.end(); ++itl) {
                        if (part::stringsMatchI(itl->second.name, sTemp, matchType)) {
                            CBitcoinAddress checkValid(itl->first);
                            if (checkValid.IsValid()) {
                                CKeyID ki;
                                checkValid.GetKeyID(ki);
                                vMatchAddress.push_back(ki);
                            } else {
                                LogPrintf("Warning: matched invalid address: %s\n", checkValid.ToString().c_str());
                            }
                        }
                    }
                }
            }
        }
    } else {
        fMatchAll = true;
    }

    size_t i = 1;
    while (i < request.params.size()) {
        sTemp = request.params[i].get_str();
        if (sTemp == "-from") {
            if (i >= request.params.size()-1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Argument required for: " + sTemp);
            }
            i++;
            sTemp = request.params[i].get_str();
            tFrom = part::strToEpoch(sTemp.c_str());
            if (tFrom < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "from format error: " + std::string(strerror(errno)));
            }
        } else
        if (sTemp == "-to") {
            if (i >= request.params.size()-1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Argument required for: " + sTemp);
            }
            i++;
            sTemp = request.params[i].get_str();
            tTo = part::strToEpoch(sTemp.c_str());
            if (tTo < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "to format error: " + std::string(strerror(errno)));
            }
        } else
        if (sTemp == "asc") {
            fDesc = false;
        } else
        if (sTemp == "desc") {
            fDesc = true;
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown parameter: " + sTemp);
        }

        i++;
    }

    if (!fMatchAll && vMatchAddress.size() < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No address found.");
    }

    UniValue result(UniValue::VOBJ);

    std::map<CKeyID, std::string> mLabelCache;
    std::vector<std::pair<int64_t, UniValue> > vMessages;

    std::vector<std::string> vPrefixes;
    vPrefixes.push_back("im");
    vPrefixes.push_back("sm");

    uint8_t chKey[30];
    size_t nMessages = 0;
    UniValue messageList(UniValue::VARR);

    size_t debugEmptySent = 0;

    {
        LOCK(smsg::cs_smsgDB);
        smsg::SecMsgDB dbMsg;
        if (!dbMsg.Open("cr")) {
            throw std::runtime_error("Could not open DB.");
        }

        std::vector<std::string>::iterator itp;
        std::vector<CKeyID>::iterator its;
        for (itp = vPrefixes.begin(); itp < vPrefixes.end(); ++itp) {
            bool fInbox = *itp == std::string("im");

            dbMsg.TxnBegin();

            leveldb::Iterator *it = dbMsg.pdb->NewIterator(leveldb::ReadOptions());
            smsg::SecMsgStored smsgStored;
            smsg::MessageData msg;

            while (dbMsg.NextSmesg(it, *itp, chKey, smsgStored)) {
                if (!fInbox && smsgStored.addrOutbox.IsNull()) {
                    debugEmptySent++;
                    continue;
                }

                uint32_t nPayload = smsgStored.vchMessage.size() - smsg::SMSG_HDR_LEN;
                int rv;
                if ((rv = smsgModule.Decrypt(false, fInbox ? smsgStored.addrTo : smsgStored.addrOutbox,
                    &smsgStored.vchMessage[0], &smsgStored.vchMessage[smsg::SMSG_HDR_LEN], nPayload, msg)) == 0) {
                    if ((tFrom > 0 && msg.timestamp < tFrom)
                        || (tTo > 0 && msg.timestamp > tTo)) {
                        continue;
                    }

                    CKeyID kiFrom;
                    CBitcoinAddress addrFrom(msg.sFromAddress);
                    if (addrFrom.IsValid()) {
                        addrFrom.GetKeyID(kiFrom);
                    }

                    if (!fMatchAll) {
                        bool fSkip = true;

                        for (its = vMatchAddress.begin(); its < vMatchAddress.end(); ++its) {
                            if (*its == kiFrom
                                || *its == smsgStored.addrTo) {
                                fSkip = false;
                                break;
                            }
                        }

                        if (fSkip) {
                            continue;
                        }
                    }

                    // Get labels for addresses, cache found labels.
                    std::string lblFrom, lblTo;
                    std::map<CKeyID, std::string>::iterator itl;

                    if ((itl = mLabelCache.find(kiFrom)) != mLabelCache.end()) {
                        lblFrom = itl->second;
                    } else {
                        LOCK(smsgModule.pwallet->cs_wallet);
                        auto mi(smsgModule.pwallet->mapAddressBook.find(PKHash(kiFrom)));
                        if (mi != smsgModule.pwallet->mapAddressBook.end()) {
                            lblFrom = mi->second.name;
                        }
                        mLabelCache[kiFrom] = lblFrom;
                    }

                    if ((itl = mLabelCache.find(smsgStored.addrTo)) != mLabelCache.end()) {
                        lblTo = itl->second;
                    } else {
                        LOCK(smsgModule.pwallet->cs_wallet);
                        auto mi(smsgModule.pwallet->mapAddressBook.find(PKHash(smsgStored.addrTo)));
                        if (mi != smsgModule.pwallet->mapAddressBook.end()) {
                            lblTo = mi->second.name;
                        }
                        mLabelCache[smsgStored.addrTo] = lblTo;
                    }

                    std::string sFrom = kiFrom.IsNull() ? "anon" : EncodeDestination(PKHash(kiFrom));
                    std::string sTo = EncodeDestination(PKHash(smsgStored.addrTo));
                    if (lblFrom.length() != 0) {
                        sFrom += " (" + lblFrom + ")";
                    }
                    if (lblTo.length() != 0) {
                        sTo += " (" + lblTo + ")";
                    }

                    UniValue objM(UniValue::VOBJ);
                    PushTime(objM, "sent", msg.timestamp);
                    objM.pushKV("from", sFrom);
                    objM.pushKV("to", sTo);
                    objM.pushKV("text", std::string((char*)&msg.vchMessage[0]));

                    vMessages.push_back(std::make_pair(msg.timestamp, objM));
                } else {
                    LogPrintf("%s: SecureMsgDecrypt failed, %s.\n", __func__, HexStr(chKey, chKey+18).c_str());
                }
            }
            delete it;

            dbMsg.TxnCommit();
        }
    } // cs_smsgDB


    std::sort(vMessages.begin(), vMessages.end(), fDesc ? sortMsgDesc : sortMsgAsc);

    std::vector<std::pair<int64_t, UniValue> >::iterator itm;
    for (itm = vMessages.begin(); itm < vMessages.end(); ++itm) {
        messageList.push_back(itm->second);
        nMessages++;
    }

    result.pushKV("messages", messageList);

    if (LogAcceptCategory(BCLog::SMSG)) {
        result.pushKV("debug empty sent", (int)debugEmptySent);
    }

    result.pushKV("result", strprintf("Displayed %u messages.", nMessages));
    if (tFrom > 0) {
        result.pushKV("from", part::GetTimeString(tFrom, cbuf, sizeof(cbuf)));
    }
    if (tTo > 0) {
        result.pushKV("to", part::GetTimeString(tTo, cbuf, sizeof(cbuf)));
    }
#else
    UniValue result(UniValue::VOBJ);
    throw JSONRPCError(RPC_MISC_ERROR, "No wallet.");
#endif
    return result;
}

static UniValue smsgone(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
        RPCHelpMan{"smsg",
                "\nView smsg by msgid.\n",
                {
                    {"msgid", RPCArg::Type::STR, RPCArg::Optional::NO, "Id of the message to view."},
                    {"options", RPCArg::Type::OBJ, /* default */ "", "",
                        {
                            {"delete", RPCArg::Type::BOOL, /* default */ "false", "Delete msg if true."},
                            {"setread", RPCArg::Type::BOOL, /* default */ "false", "Set read status to value."},
                            {"encoding", RPCArg::Type::STR, /* default */ "text", "Display message data in encoding, values: \"text\", \"hex\", \"none\"."},
                        },
                        "options"},
                },
                RPCResult{
            "{\n"
            "  \"msgid\": \"...\"                    (string) The message identifier\n"
            "  \"version\": \"str\"                  (string) The message version\n"
            "  \"location\": \"str\"                 (string) inbox|outbox|sending\n"
            "  \"received\": int                     (int) Time the message was received\n"
            "  \"to\": \"str\"                       (string) Address the message was sent to\n"
            "  \"read\": bool                        (bool) Read status\n"
            "  \"sent\": int                         (int) Time the message was created\n"
            "  \"paid\": bool                        (bool) Paid or free message\n"
            "  \"daysretention\": int                (int) Number of days message will stay in the network for\n"
            "  \"expiration\": int                   (int) Time the message will be dropped from the network\n"
            "  \"payloadsize\": int                  (int) Size of user message\n"
            "  \"from\": \"str\"                     (string) Address the message was sent from\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("smsg", "\"msgid\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("smsg", "\"msgid\"")
                },
            }.ToString());

    EnsureSMSGIsEnabled();

    RPCTypeCheckObj(request.params,
        {
            {"msgid",             UniValueType(UniValue::VSTR)},
            {"option",            UniValueType(UniValue::VOBJ)},
        }, true, false);

    std::string sMsgId = request.params[0].get_str();

    if (!IsHex(sMsgId) || sMsgId.size() != 56) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "msgid must be 28 bytes in hex string.");
    }
    std::vector<uint8_t> vMsgId = ParseHex(sMsgId.c_str());
    std::string sType;

    uint8_t chKey[30];
    chKey[1] = 'm';
    memcpy(chKey+2, vMsgId.data(), 28);
    smsg::SecMsgStored smsgStored;
    UniValue result(UniValue::VOBJ);

    UniValue options = request.params[1];
    {
        LOCK(smsg::cs_smsgDB);
        smsg::SecMsgDB dbMsg;
        if (!dbMsg.Open("cr+"))
            throw std::runtime_error("Could not open DB.");

        if ((chKey[0] = 'i') && dbMsg.ReadSmesg(chKey, smsgStored)) {
            sType = "inbox";
        } else
        if ((chKey[0] = 's') && dbMsg.ReadSmesg(chKey, smsgStored)) {
            sType = "outbox";
        } else
        if ((chKey[0] = 'q') && dbMsg.ReadSmesg(chKey, smsgStored)) {
            sType = "sending";
        } else {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unknown message id.");
        };

        if (options.isObject()) {
            options = request.params[1].get_obj();
            if (options["delete"].isBool() && options["delete"].get_bool() == true) {
                if (!dbMsg.EraseSmesg(chKey)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "EraseSmesg failed.");
                }
                result.pushKV("operation", "Deleted");
            } else {
                // Can't mix delete and other operations
                if (options["setread"].isBool()) {
                    bool nv = options["setread"].get_bool();
                    if (nv) {
                        smsgStored.status &= ~SMSG_MASK_UNREAD;
                    } else {
                        smsgStored.status |= SMSG_MASK_UNREAD;
                    }

                    if (!dbMsg.WriteSmesg(chKey, smsgStored)) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "WriteSmesg failed.");
                    }
                    result.pushKV("operation", strprintf("Set read status to: %s", nv ? "true" : "false"));
                }
            }
        }
    }

    const smsg::SecureMessage *psmsg = (smsg::SecureMessage*) &smsgStored.vchMessage[0];

    result.pushKV("msgid", sMsgId);
    result.pushKV("version", strprintf("%02x%02x", psmsg->version[0], psmsg->version[1]));
    result.pushKV("location", sType);
    PushTime(result, "received", smsgStored.timeReceived);
    result.pushKV("to", EncodeDestination(PKHash(smsgStored.addrTo)));
    //result.pushKV("addressoutbox", CBitcoinAddress(smsgStored.addrOutbox).ToString());
    result.pushKV("read", UniValue(bool(!(smsgStored.status & SMSG_MASK_UNREAD))));

    PushTime(result, "sent", psmsg->timestamp);
    result.pushKV("paid", UniValue(psmsg->IsPaidVersion()));

    uint32_t nDaysRetention = psmsg->IsPaidVersion() ? psmsg->nonce[0] : 2;
    int64_t ttl = smsg::SMSGGetSecondsInDay() * nDaysRetention;
    result.pushKV("daysretention", (int)nDaysRetention);
    PushTime(result, "expiration", psmsg->timestamp + ttl);


    smsg::MessageData msg;
    bool fInbox = sType == "inbox" ? true : false;
    uint32_t nPayload = smsgStored.vchMessage.size() - smsg::SMSG_HDR_LEN;
    result.pushKV("payloadsize", (int)nPayload);

    std::string sEnc;
    if (options.isObject() && options["encoding"].isStr()) {
        sEnc = options["encoding"].get_str();
    }

    int rv;
    if ((rv = smsgModule.Decrypt(false, fInbox ? smsgStored.addrTo : smsgStored.addrOutbox,
        &smsgStored.vchMessage[0], &smsgStored.vchMessage[smsg::SMSG_HDR_LEN], nPayload, msg)) == 0) {
        result.pushKV("from", msg.sFromAddress);

        if (sEnc == "none") {
        } else
        if (sEnc == "") {
            // TODO: detect non ascii chars
            if (msg.vchMessage.size() < smsg::SMSG_MAX_MSG_BYTES) {
                result.pushKV("text", std::string((char*)msg.vchMessage.data()));
            } else {
                result.pushKV("hex", HexStr(msg.vchMessage));
            }
        } else
        if (sEnc == "text") {
            result.pushKV("text", std::string((char*)msg.vchMessage.data()));
        } else
        if (sEnc == "hex") {
            result.pushKV("hex", HexStr(msg.vchMessage));
        } else {
            result.pushKV("unknown_encoding", sEnc);
        }
    } else {
        result.pushKV("error", "decrypt failed");
    }

    return result;
}

static UniValue smsgimport(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
        RPCHelpMan{"smsgimport",
                "\nImport smsg from hex string.\n",
                {
                    {"msg", RPCArg::Type::STR, RPCArg::Optional::NO, "Hex encoded smsg."},
                    {"options", RPCArg::Type::OBJ, /* default */ "", "",
                        {
                            //{"submitmsg", RPCArg::Type::BOOL, /* default */ "false", "Submit msg to network if true."},
                            {"setread", RPCArg::Type::BOOL, /* default */ "false", "Set read status to value."},
                        },
                        "options"},
                },
                RPCResult{
            "{\n"
            "  \"msgid\": \"...\"                    (string) The message identifier\n"
            "}\n"
                },
                RPCExamples{
            HelpExampleCli("smsgimport", "\"msg\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("smsgimport", "\"msg\"")
                },
            }.ToString());

    EnsureSMSGIsEnabled();

    RPCTypeCheckObj(request.params,
        {
            {"msg",             UniValueType(UniValue::VSTR)},
            {"option",            UniValueType(UniValue::VOBJ)},
        }, true, false);

    std::string str_msg = request.params[0].get_str();

    if (!IsHex(str_msg)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "msg must be a hex string.");
    }

    std::vector<uint8_t> vsmsg = ParseHex(str_msg.c_str());
    smsg::SecureMessage smsg;
    memcpy(smsg.data(), vsmsg.data(), smsg::SMSG_HDR_LEN);
    smsg.pPayload = vsmsg.data() + smsg::SMSG_HDR_LEN;

    UniValue result(UniValue::VOBJ);
    std::string str_error;
    bool setread = false;
    UniValue options = request.params[1];
    if (options.isObject() && options["setread"].isBool()) {
        setread = options["setread"].get_bool();
    }

    if (smsgModule.Import(&smsg, str_error, setread) != 0) {
        smsg.pPayload = nullptr;
        throw JSONRPCError(RPC_MISC_ERROR, "Import failed: " + str_error);
    }
    result.pushKV("msgid", HexStr(smsgModule.GetMsgID(smsg)));

    smsg.pPayload = nullptr;

    return result;
}

static UniValue smsgpurge(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            RPCHelpMan{"smsgpurge",
                "\nPurge smsg by msgid.\n",
                {
                    {"msgid", RPCArg::Type::STR_HEX, /* default */ "", "Id of the message to purge."},
                },
                RPCResults{},
                RPCExamples{
            HelpExampleCli("smsgpurge", "\"msgid\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("smsgpurge", "\"msgid\"")
                },
            }.ToString());

    EnsureSMSGIsEnabled();

    if (!request.params[0].isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "msgid must be a string.");
    }

    std::string sMsgId = request.params[0].get_str();

    if (!IsHex(sMsgId) || sMsgId.size() != 56) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "msgid must be 28 bytes in hex string.");
    }
    std::vector<uint8_t> vMsgId = ParseHex(sMsgId.c_str());

    std::string sError;
    if (smsg::SMSG_NO_ERROR != smsgModule.Purge(vMsgId, sError)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Error: " + sError);
    }

    return NullUniValue;
}

static UniValue smsggetfeerate(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            RPCHelpMan{"smsggetfeerate",
                "\nReturn paid SMSG fee.\n",
                {
                    {"height", RPCArg::Type::STR_HEX, /* default */ "", "Chain height to get fee rate for."},
                },
                RPCResult{
            "Fee rate in satoshis."
                },
                RPCExamples{
            HelpExampleCli("smsggetfeerate", "1000") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("smsggetfeerate", "1000")
                },
            }.ToString());

    LOCK(cs_main);

    CBlockIndex *pblockindex = nullptr;
    if (!request.params[0].isNull()) {
        int nHeight = request.params[0].get_int();
        if (nHeight > ::ChainActive().Height()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
        }
        pblockindex = ::ChainActive()[nHeight];
    }

    return GetSmsgFeeRate(pblockindex);
}

static UniValue smsggetdifficulty(const JSONRPCRequest &request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            RPCHelpMan{"smsggetdifficulty",
                "\nReturn free SMSG difficulty.\n",
                {
                    {"time", RPCArg::Type::STR_HEX, /* default */ "", "Chain time to get smsg difficulty for."},
                },
                RPCResult{
            "Difficulty."
                },
                RPCExamples{
            HelpExampleCli("smsggetdifficulty", "1552688834") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("smsggetdifficulty", "1552688834")
                },
            }.ToString());

    LOCK(cs_main);

    int64_t chain_time = ::ChainActive().Tip()->nTime;
    if (!request.params[0].isNull()) {
        chain_time = request.params[0].get_int64();
        if (chain_time > ::ChainActive().Tip()->nTime) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Time out of range");
        }
    }

    uint32_t target_compact = GetSmsgDifficulty(chain_time);
    return smsg::GetDifficulty(target_compact);
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "smsg",               "smsgenable",             &smsgenable,             {"walletname"} },
    { "smsg",               "smsgdisable",            &smsgdisable,            {} },
    { "smsg",               "smsgoptions",            &smsgoptions,            {} },
    { "smsg",               "smsglocalkeys",          &smsglocalkeys,          {} },
    { "smsg",               "smsgscanchain",          &smsgscanchain,          {} },
    { "smsg",               "smsgscanbuckets",        &smsgscanbuckets,        {} },
    { "smsg",               "smsgaddaddress",         &smsgaddaddress,         {"address","pubkey"} },
    { "smsg",               "smsgaddlocaladdress",    &smsgaddlocaladdress,    {"address"} },
    { "smsg",               "smsgimportprivkey",      &smsgimportprivkey,      {"privkey","label"} },
    { "smsg",               "smsggetpubkey",          &smsggetpubkey,          {"address"} },
    { "smsg",               "smsgsend",               &smsgsend,               {"address_from","address_to","message","paid_msg","days_retention","testfee","fromfile","decodehex","submitmsg","savemsg"} },
    { "smsg",               "smsgsendanon",           &smsgsendanon,           {"address_to","message"} },
    { "smsg",               "smsginbox",              &smsginbox,              {"mode","filter","options"} },
    { "smsg",               "smsgoutbox",             &smsgoutbox,             {"mode","filter","options"} },
    { "smsg",               "smsgbuckets",            &smsgbuckets,            {"mode"} },
    { "smsg",               "smsgview",               &smsgview,               {}},
    { "smsg",               "smsg",                   &smsgone,                {"msgid","options"}},
    { "smsg",               "smsgimport",             &smsgimport,             {"msg","options"}},
    { "smsg",               "smsgpurge",              &smsgpurge,              {"msgid"}},
    { "smsg",               "smsggetfeerate",         &smsggetfeerate,         {"height"}},
    { "smsg",               "smsggetdifficulty",      &smsggetdifficulty,      {"time"}},
};

void RegisterSmsgRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
