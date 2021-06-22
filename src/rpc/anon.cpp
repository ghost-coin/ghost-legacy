// Copyright (c) 2017-2020 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/util.h>

#include <validation.h>
#include <txdb.h>


static bool IsDigits(const std::string &str)
{
    return str.length() && std::all_of(str.begin(), str.end(), ::isdigit);
};

UniValue anonoutput(const JSONRPCRequest &request)
{
            RPCHelpMan{"anonoutput",
                "\nReturns an anon output at index or by publickey hex.\n"
                "If no output is provided returns the last index.\n",
                {
                    {"output", RPCArg::Type::STR, /* default */ "", "Output to view, specified by index or hex of publickey."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "index", "Position in chain of anon output"},
                        {RPCResult::Type::STR_HEX, "publickey", "Public key of anon out"},
                        {RPCResult::Type::STR_HEX, "txnhash", "Hash of transaction found in"},
                        {RPCResult::Type::NUM, "n", "Offset in transaction found in"},
                        {RPCResult::Type::NUM, "blockheight", "Height of block found in"},
                }},
                RPCExamples{
            HelpExampleCli("anonoutput", "\"1\"")
            + HelpExampleRpc("anonoutput", "\"2\"")
            },
        }.Check(request);

    UniValue result(UniValue::VOBJ);

    if (request.params.size() == 0) {
        LOCK(cs_main);
        result.pushKV("lastindex", (int)::ChainActive().Tip()->nAnonOutputs);
        return result;
    }

    std::string sIn = request.params[0].get_str();

    int64_t nIndex;
    if (IsDigits(sIn)) {
        if (!ParseInt64(sIn, &nIndex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid index");
        }
    } else {
        if (!IsHex(sIn)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, sIn + " is not a hexadecimal or decimal string.");
        }
        std::vector<uint8_t> vIn = ParseHex(sIn);

        CCmpPubKey pk(vIn.begin(), vIn.end());

        if (!pk.IsValid()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, sIn + " is not a valid compressed public key.");
        }

        if (!pblocktree->ReadRCTOutputLink(pk, nIndex)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Output not indexed.");
        }
    }

    CAnonOutput ao;
    if (!pblocktree->ReadRCTOutput(nIndex, ao)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Unknown index.");
    }

    result.pushKV("index", (int)nIndex);
    result.pushKV("publickey", HexStr(Span<const unsigned char>(ao.pubkey.begin(), 33)));
    result.pushKV("txnhash", ao.outpoint.hash.ToString());
    result.pushKV("n", (int)ao.outpoint.n);
    result.pushKV("blockheight", ao.nBlockHeight);

    return result;
};

UniValue checkkeyimage(const JSONRPCRequest &request)
{
        RPCHelpMan{"checkkeyimage",
            "\nCheck if keyimage is spent in the chain.\n",
            {
                {"keyimage", RPCArg::Type::STR, RPCArg::Optional::NO, "Hex encoded keyimage."},
            },
            RPCResult{
                RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::BOOL, "spent", "Keyimage found in chain or not"},
                    {RPCResult::Type::STR_HEX, "txid", "ID of spending transaction"},
            }},
            RPCExamples{
        HelpExampleCli("checkkeyimage", "\"keyimage\"")
        + HelpExampleRpc("checkkeyimage", "\"keyimage\"")
        },
    }.Check(request);

    RPCTypeCheck(request.params, {UniValue::VSTR}, true);
    UniValue result(UniValue::VOBJ);

    std::string s = request.params[0].get_str();
    if (!IsHex(s) || !(s.size() == 66)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Keyimage must be 33 bytes and hex encoded.");
    }

    std::vector<uint8_t> v = ParseHex(s);
    CCmpPubKey ki(v.begin(), v.end());

    uint256 txhashKI;
    bool spent_in_chain = pblocktree->ReadRCTKeyImage(ki, txhashKI);

    result.pushKV("spent", spent_in_chain);
    if (spent_in_chain) {
        result.pushKV("txid", txhashKI.ToString());
    }

    return result;
};

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "anon",               "anonoutput",             &anonoutput,             {"output"} },
    { "anon",               "checkkeyimage",          &checkkeyimage,          {"keyimage"} },
};

void RegisterAnonRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
