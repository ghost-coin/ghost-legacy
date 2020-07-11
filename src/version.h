// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

/**
 * network protocol versioning
 */

static const int PROTOCOL_VERSION = 90011;

//! initial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 209;

//! In this version, 'getheaders' was introduced.
static const int GETHEADERS_VERSION = 31800;

//! disconnect from peers older than this proto version
static const int MIN_PEER_PROTO_VERSION = PROTOCOL_VERSION - 1;

//! nTime field added to CAddress, starting with this version;
//! if possible, avoid requesting addresses nodes older than this
static const int CADDR_TIME_VERSION = 31402;

//! BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 60000;

//! "filter*" commands are disabled without NODE_BLOOM after and including this version
static const int NO_BLOOM_VERSION = 70011;

//! "sendheaders" command and announcing blocks with headers starts with this version
static const int SENDHEADERS_VERSION = 70012;

//! "feefilter" tells peers to filter invs to you by fee starts with this version
static const int FEEFILTER_VERSION = 70013;

//! short-id-based block download starts with this version
static const int SHORT_IDS_BLOCKS_VERSION = 70014;

//! not banning for invalid compact blocks starts with this version
static const int INVALID_CB_NO_BAN_VERSION = 70015;

//! minimum ProTx proto version
static const int MIN_PROTX_PROTO_VERSION = 70211;

//! maximum ProTx proto version (slightly higher then current PROTOCOL_VERSION to ensure masternodes can upgrade)
static const int MAX_PROTX_PROTO_VERSION = PROTOCOL_VERSION + 2;

//! introduction of DIP3/deterministic masternodes
static const int DMN_PROTO_VERSION = 70213;

//! introduction of LLMQs
static const int LLMQS_PROTO_VERSION = 70214;

//! minimum proto version of masternode to accept in DKGs
static const int MIN_MASTERNODE_PROTO_VERSION = LLMQS_PROTO_VERSION;

#endif // BITCOIN_VERSION_H
