// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/client.h>
#include <util/system.h>

#include <set>
#include <stdint.h>

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
    std::string paramName;  //!< parameter name
};

// clang-format off
/**
 * Specify a (method, idx, name) here if the argument is a non-string RPC
 * argument and needs to be converted from JSON.
 *
 * @note Parameter indexes start from 0.
 */
static const CRPCConvertParam vRPCConvertParams[] =
{
    { "setmocktime", 0, "timestamp" },
    { "setmocktime", 1, "is_offset" },
    { "mockscheduler", 0, "delta_time" },
    { "utxoupdatepsbt", 1, "descriptors" },
    { "generatetoaddress", 0, "nblocks" },
    { "generatetoaddress", 2, "maxtries" },
    { "generatetodescriptor", 0, "num_blocks" },
    { "generatetodescriptor", 2, "maxtries" },
    { "generateblock", 1, "transactions" },
    { "getnetworkhashps", 0, "nblocks" },
    { "getnetworkhashps", 1, "height" },
    { "sendtoaddress", 1, "amount" },
    { "sendtoaddress", 4, "subtractfeefromamount" },
    { "sendtoaddress", 6 , "replaceable" },
    { "sendtoaddress", 7 , "conf_target" },
    { "sendtoaddress", 9, "avoid_reuse" },
    { "settxfee", 0, "amount" },
    { "sethdseed", 0, "newkeypool" },
    { "getreceivedbyaddress", 1, "minconf" },
    { "getreceivedbylabel", 1, "minconf" },
    { "listreceivedbyaddress", 0, "minconf" },
    { "listreceivedbyaddress", 1, "include_empty" },
    { "listreceivedbyaddress", 2, "include_watchonly" },
    { "listreceivedbylabel", 0, "minconf" },
    { "listreceivedbylabel", 1, "include_empty" },
    { "listreceivedbylabel", 2, "include_watchonly" },
    { "getbalance", 1, "minconf" },
    { "getbalance", 2, "include_watchonly" },
    { "getbalance", 3, "avoid_reuse" },
    { "getblockhash", 0, "height" },
    { "waitforblockheight", 0, "height" },
    { "waitforblockheight", 1, "timeout" },
    { "waitforblock", 1, "timeout" },
    { "waitfornewblock", 0, "timeout" },
    { "listtransactions", 1, "count" },
    { "listtransactions", 2, "skip" },
    { "listtransactions", 3, "include_watchonly" },
    { "walletpassphrase", 1, "timeout" },
    { "walletpassphrase", 2, "stakingonly" },
    { "getblocktemplate", 0, "template_request" },
    { "listsinceblock", 1, "target_confirmations" },
    { "listsinceblock", 2, "include_watchonly" },
    { "listsinceblock", 3, "include_removed" },
    { "sendmany", 1, "amounts" },
    { "sendmany", 2, "minconf" },
    { "sendmany", 4, "subtractfeefrom" },
    { "sendmany", 5 , "replaceable" },
    { "sendmany", 6 , "conf_target" },
    { "deriveaddresses", 1, "range" },
    { "scantxoutset", 1, "scanobjects" },
    { "addmultisigaddress", 0, "nrequired" },
    { "addmultisigaddress", 1, "keys" },
    { "addmultisigaddress", 3, "bech32" },
    { "addmultisigaddress", 4, "256bit" },
    { "createmultisig", 0, "nrequired" },
    { "createmultisig", 1, "keys" },
    { "validateaddress", 1, "showaltversions" },
    { "listunspent", 0, "minconf" },
    { "listunspent", 1, "maxconf" },
    { "listunspent", 2, "addresses" },
    { "listunspent", 3, "include_unsafe" },
    { "listunspent", 4, "query_options" },
    { "getblock", 1, "verbosity" },
    { "getblock", 1, "verbose" },
    { "getblock", 2, "coinstakeinfo" },
    { "getblockheader", 1, "verbose" },
    { "getchaintxstats", 0, "nblocks" },
    { "gettransaction", 1, "include_watchonly" },
    { "gettransaction", 2, "verbose" },
    { "getrawtransaction", 1, "verbose" },
    { "createrawtransaction", 0, "inputs" },
    { "createrawtransaction", 1, "outputs" },
    { "createrawtransaction", 2, "locktime" },
    { "createrawtransaction", 3, "replaceable" },
    { "decoderawtransaction", 1, "iswitness" },
    { "signrawtransactionwithkey", 1, "privkeys" },
    { "signrawtransactionwithkey", 2, "prevtxs" },
    { "signrawtransactionwithwallet", 1, "prevtxs" },
    { "sendrawtransaction", 1, "maxfeerate" },
    { "testmempoolaccept", 0, "rawtxs" },
    { "testmempoolaccept", 1, "maxfeerate" },
    { "testmempoolaccept", 2, "ignorelocks" },
    { "combinerawtransaction", 0, "txs" },
    { "fundrawtransaction", 1, "options" },
    { "fundrawtransaction", 2, "iswitness" },
    { "walletcreatefundedpsbt", 0, "inputs" },
    { "walletcreatefundedpsbt", 1, "outputs" },
    { "walletcreatefundedpsbt", 2, "locktime" },
    { "walletcreatefundedpsbt", 3, "options" },
    { "walletcreatefundedpsbt", 4, "bip32derivs" },
    { "walletprocesspsbt", 1, "sign" },
    { "walletprocesspsbt", 3, "bip32derivs" },
    { "createpsbt", 0, "inputs" },
    { "createpsbt", 1, "outputs" },
    { "createpsbt", 2, "locktime" },
    { "createpsbt", 3, "replaceable" },
    { "combinepsbt", 0, "txs"},
    { "joinpsbts", 0, "txs"},
    { "finalizepsbt", 1, "extract"},
    { "converttopsbt", 1, "permitsigdata"},
    { "converttopsbt", 2, "iswitness"},
    { "gettxout", 1, "n" },
    { "gettxout", 2, "include_mempool" },
    { "gettxoutproof", 0, "txids" },
    { "lockunspent", 0, "unlock" },
    { "lockunspent", 1, "transactions" },
    { "lockunspent", 2, "permanent" },
    { "importprivkey", 2, "rescan" },
    { "importaddress", 2, "rescan" },
    { "importaddress", 3, "p2sh" },
    { "importpubkey", 2, "rescan" },
    { "importmulti", 0, "requests" },
    { "importmulti", 1, "options" },
    { "importdescriptors", 0, "requests" },
    { "verifychain", 0, "checklevel" },
    { "verifychain", 1, "nblocks" },
    { "getblockstats", 0, "hash_or_height" },
    { "getblockstats", 1, "stats" },
    { "pruneblockchain", 0, "height" },
    { "keypoolrefill", 0, "newsize" },
    { "getrawmempool", 0, "verbose" },
    { "estimatesmartfee", 0, "conf_target" },
    { "estimaterawfee", 0, "conf_target" },
    { "estimaterawfee", 1, "threshold" },
    { "prioritisetransaction", 1, "dummy" },
    { "prioritisetransaction", 2, "fee_delta" },
    { "setban", 2, "bantime" },
    { "setban", 3, "absolute" },
    { "setnetworkactive", 0, "state" },
    { "setwalletflag", 1, "value" },
    { "getmempoolancestors", 1, "verbose" },
    { "getmempooldescendants", 1, "verbose" },
    { "getblockhashes", 0 , "high"},
    { "getblockhashes", 1, "low"},
    { "getblockhashes", 2, "options" },
    { "getspentinfo", 0, "inputs"},
    { "getaddresstxids", 0, "addresses"},
    { "getaddressbalance", 0, "addresses"},
    { "getaddressdeltas", 0, "addresses"},
    { "getaddressutxos", 0, "addresses"},
    { "getaddressmempool", 0, "addresses"},
    { "listcoldstakeunspent", 1, "height"},
    { "listcoldstakeunspent", 2, "options"},
    { "getblockreward", 0, "height"},
    { "bumpfee", 1, "options" },


    { "reservebalance", 0, "enabled" },
    { "deriverangekeys", 0, "start" },
    { "deriverangekeys", 1, "end" },
    { "filtertransactions", 0, "options" },
    { "filteraddresses", 0, "offset" },
    { "filteraddresses", 1, "count" },
    { "setvote", 0, "proposal" },
    { "setvote", 1, "option" },
    { "setvote", 2, "height_start" },
    { "setvote", 3, "height_end" },
    { "tallyvotes", 0, "proposal" },
    { "tallyvotes", 1, "height_start" },
    { "tallyvotes", 2, "height_end" },


    { "sendghosttoblind", 1, "amount" },
    { "sendghosttoblind", 4, "subtractfeefromamount" },
    { "sendghosttoanon", 1, "amount" },
    { "sendghosttoanon", 4, "subtractfeefromamount" },

    { "sendblindtoghost", 1, "amount" },
    { "sendblindtoghost", 4, "subtractfeefromamount" },
    { "sendblindtoblind", 1, "amount" },
    { "sendblindtoblind", 4, "subtractfeefromamount" },
    { "sendblindtoanon", 1, "amount" },
    { "sendblindtoanon", 4, "subtractfeefromamount" },

    { "sendanontoghost", 1, "amount" },
    { "sendanontoghost", 4, "subtractfeefromamount" },
    { "sendanontoghost", 6, "ringsize" },
    { "sendanontoghost", 7, "inputs_per_sig" },

    { "sendanontoblind", 1, "amount" },
    { "sendanontoblind", 4, "subtractfeefromamount" },
    { "sendanontoblind", 6, "ringsize" },
    { "sendanontoblind", 7, "inputs_per_sig" },

    { "sendanontoanon", 1, "amount" },
    { "sendanontoanon", 4, "subtractfeefromamount" },
    { "sendanontoanon", 6, "ringsize" },
    { "sendanontoanon", 7, "inputs_per_sig" },

    { "sendtypeto", 2, "outputs" },
    { "sendtypeto", 5, "ringsize" },
    { "sendtypeto", 6, "inputs_per_sig" },
    { "sendtypeto", 7, "test_fee" },
    { "sendtypeto", 8, "coincontrol" },

    { "buildscript", 0, "json" },
    { "createsignaturewithwallet", 1, "prevtx" },
    { "createsignaturewithkey", 1, "prevtx" },
    { "createsignaturewithwallet", 4, "options" },
    { "createsignaturewithkey", 4, "options" },


    { "walletsettings", 1, "json" },

    { "getnewextaddress", 2, "bech32" },
    { "getnewextaddress", 3, "hardened" },
    { "getnewstealthaddress", 3, "bech32" },
    { "getnewstealthaddress", 4, "makeV2" },
    { "importstealthaddress", 5, "bech32" },
    { "liststealthaddresses", 1, "options" },

    { "listunspentanon", 0, "minconf" },
    { "listunspentanon", 1, "maxconf" },
    { "listunspentanon", 2, "addresses" },
    { "listunspentanon", 3, "include_unsafe" },
    { "listunspentanon", 4, "query_options" },

    { "listunspentblind", 0, "minconf" },
    { "listunspentblind", 1, "maxconf" },
    { "listunspentblind", 2, "addresses" },
    { "listunspentblind", 3, "include_unsafe" },
    { "listunspentblind", 4, "query_options" },

    { "rewindchain", 0, "height" },

    { "createrawparttransaction", 0, "inputs" },
    { "createrawparttransaction", 1, "outputs" },
    { "createrawparttransaction", 2, "locktime" },
    { "createrawparttransaction", 3, "replaceable" },
    { "fundrawtransactionfrom", 2, "input_amounts" },
    { "fundrawtransactionfrom", 3, "output_amounts" },
    { "fundrawtransactionfrom", 4, "options" },

    { "verifyrawtransaction", 1, "prevtxs" },
    { "verifyrawtransaction", 2, "options" },

    { "generatematchingblindfactor", 0, "inputs" },
    { "generatematchingblindfactor", 1, "outputs" },


    { "smsgsend", 3, "paid_msg" },
    { "smsgsend", 4, "days_retention" },
    { "smsgsend", 5, "testfee" },
    { "smsgsend", 6, "options" },
    { "smsgsend", 7, "coincontrol" },
    { "smsg", 1, "options" },
    { "smsgimport", 1, "options" },
    { "smsginbox", 2, "options" },
    { "smsgoutbox", 2, "options" },
    { "smsggetfeerate", 0, "height" },
    { "smsggetdifficulty", 0, "time" },
    { "smsgscanbuckets", 0, "options" },
    { "smsgpeers", 0, "index" },
    { "smsgzmqpush", 0, "options" },


    { "devicesignrawtransaction", 1, "prevtxs" },
    { "devicesignrawtransaction", 2, "privkeypaths" },
    { "initaccountfromdevice", 2, "makedefault" },
    { "initaccountfromdevice", 3, "scan_chain_from" },
    { "initaccountfromdevice", 4, "initstealthchain" },


    { "logging", 0, "include" },
    { "logging", 1, "exclude" },
    { "disconnectnode", 1, "nodeid" },
    { "upgradewallet", 0, "version" },
    // Echo with conversion (For testing only)
    { "echojson", 0, "arg0" },
    { "echojson", 1, "arg1" },
    { "echojson", 2, "arg2" },
    { "echojson", 3, "arg3" },
    { "echojson", 4, "arg4" },
    { "echojson", 5, "arg5" },
    { "echojson", 6, "arg6" },
    { "echojson", 7, "arg7" },
    { "echojson", 8, "arg8" },
    { "echojson", 9, "arg9" },
    { "rescanblockchain", 0, "start_height"},
    { "rescanblockchain", 1, "stop_height"},
    { "createwallet", 1, "disable_private_keys"},
    { "createwallet", 2, "blank"},
    { "createwallet", 4, "avoid_reuse"},
    { "createwallet", 5, "descriptors"},
    { "getnodeaddresses", 0, "count"},
    { "stop", 0, "wait" },
};
// clang-format on

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int>> members;
    std::set<std::pair<std::string, std::string>> membersByName;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx) {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
    bool convert(const std::string& method, const std::string& name) {
        return (membersByName.count(std::make_pair(method, name)) > 0);
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    const unsigned int n_elem =
        (sizeof(vRPCConvertParams) / sizeof(vRPCConvertParams[0]));

    for (unsigned int i = 0; i < n_elem; i++) {
        members.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                      vRPCConvertParams[i].paramIdx));
        membersByName.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                            vRPCConvertParams[i].paramName));
    }
}

static CRPCConvertTable rpcCvtTable;

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(const std::string& strVal)
{
    UniValue jVal;
    if (!jVal.read(std::string("[")+strVal+std::string("]")) ||
        !jVal.isArray() || jVal.size()!=1)
        throw std::runtime_error(std::string("Error parsing JSON:")+strVal);
    return jVal[0];
}

UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];

        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}

UniValue RPCConvertNamedValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VOBJ);

    for (const std::string &s: strParams) {
        size_t pos = s.find('=');
        if (pos == std::string::npos) {
            throw(std::runtime_error("No '=' in named argument '"+s+"', this needs to be present for every argument (even if it is empty)"));
        }

        std::string name = s.substr(0, pos);
        std::string value = s.substr(pos+1);

        if (!rpcCvtTable.convert(strMethod, name)) {
            // insert string value directly
            params.pushKV(name, value);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.pushKV(name, ParseNonRFCJSONValue(value));
        }
    }

    return params;
}
