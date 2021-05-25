// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_RPC_RPCUTIL_H
#define PARTICL_RPC_RPCUTIL_H

#include <univalue.h>
#include <string>

class JSONRPCRequest;

void CallRPCVoid(std::string args, std::string wallet="", bool force_wallet=false);
void CallRPCVoidRv(std::string args, std::string wallet, bool *passed, UniValue *rv, bool force_wallet=false);
UniValue CallRPC(std::string args, std::string wallet="", bool force_wallet=false);

void AddUri(JSONRPCRequest &request, std::string wallet, bool force_wallet=false);
void CallRPC(UniValue &rv, const JSONRPCRequest &request);

#endif // PARTICL_RPC_RPCUTIL_H

