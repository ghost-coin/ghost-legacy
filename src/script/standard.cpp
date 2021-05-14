// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/standard.h>

#include <crypto/sha256.h>
#include <pubkey.h>
#include <script/script.h>

#include <string>

#include <key/extkey.h>
#include <key/stealth.h>

typedef std::vector<unsigned char> valtype;

bool fAcceptDatacarrier = DEFAULT_ACCEPT_DATACARRIER;
unsigned nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY;

CScriptID::CScriptID(const CScript& in) : BaseHash(Hash160(in)) {}
CScriptID::CScriptID(const ScriptHash& in) : BaseHash(static_cast<uint160>(in)) {}

bool CScriptID::Set(const uint256& in)
{
    CRIPEMD160().Write(in.begin(), 32).Finalize(this->begin());
    return true;
};

bool CScriptID256::Set(const CScript& in)
{
    *this = CScriptID256(HashSha256(in.begin(), in.end()));
    return true;
};

ScriptHash::ScriptHash(const CScript& in) : BaseHash(Hash160(in)) {}
ScriptHash::ScriptHash(const CScriptID& in) : BaseHash(static_cast<uint160>(in)) {}

PKHash::PKHash(const CPubKey& pubkey) : BaseHash(pubkey.GetID()) {}
PKHash::PKHash(const CKeyID& pubkey_id) : BaseHash(pubkey_id) {}

WitnessV0KeyHash::WitnessV0KeyHash(const CPubKey& pubkey) : BaseHash(pubkey.GetID()) {}
WitnessV0KeyHash::WitnessV0KeyHash(const PKHash& pubkey_hash) : BaseHash(static_cast<uint160>(pubkey_hash)) {}

CKeyID ToKeyID(const PKHash& key_hash)
{
    return CKeyID{static_cast<uint160>(key_hash)};
}

CKeyID ToKeyID(const WitnessV0KeyHash& key_hash)
{
    return CKeyID{static_cast<uint160>(key_hash)};
}

WitnessV0ScriptHash::WitnessV0ScriptHash(const CScript& in)
{
    CSHA256().Write(in.data(), in.size()).Finalize(begin());
}

std::string GetTxnOutputType(TxoutType t)
{
    switch (t)
    {
    case TxoutType::NONSTANDARD: return "nonstandard";
    case TxoutType::PUBKEY: return "pubkey";
    case TxoutType::PUBKEYHASH: return "pubkeyhash";
    case TxoutType::SCRIPTHASH: return "scripthash";
    case TxoutType::MULTISIG: return "multisig";
    case TxoutType::NULL_DATA: return "nulldata";
    case TxoutType::WITNESS_V0_KEYHASH: return "witness_v0_keyhash";
    case TxoutType::WITNESS_V0_SCRIPTHASH: return "witness_v0_scripthash";
    case TxoutType::WITNESS_V1_TAPROOT: return "witness_v1_taproot";
    case TxoutType::WITNESS_UNKNOWN: return "witness_unknown";

    case TxoutType::SCRIPTHASH256: return "scripthash256";
    case TxoutType::PUBKEYHASH256: return "pubkeyhash256";
    case TxoutType::TIMELOCKED_SCRIPTHASH: return "timelocked_scripthash";
    case TxoutType::TIMELOCKED_SCRIPTHASH256: return "timelocked_scripthash256";
    case TxoutType::TIMELOCKED_PUBKEYHASH: return "timelocked_pubkeyhash";
    case TxoutType::TIMELOCKED_PUBKEYHASH256: return "timelocked_pubkeyhash256";
    case TxoutType::TIMELOCKED_MULTISIG: return "timelocked_multisig";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

static bool MatchPayToPubkey(const CScript& script, valtype& pubkey)
{
    if (script.size() == CPubKey::SIZE + 2 && script[0] == CPubKey::SIZE && script.back() == OP_CHECKSIG) {
        pubkey = valtype(script.begin() + 1, script.begin() + CPubKey::SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }
    if (script.size() == CPubKey::COMPRESSED_SIZE + 2 && script[0] == CPubKey::COMPRESSED_SIZE && script.back() == OP_CHECKSIG) {
        pubkey = valtype(script.begin() + 1, script.begin() + CPubKey::COMPRESSED_SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }
    return false;
}

static bool MatchPayToPubkeyHash(const CScript& script, valtype& pubkeyhash)
{
    if (script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == 20 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG) {
        pubkeyhash = valtype(script.begin () + 3, script.begin() + 23);
        return true;
    }
    return false;
}

static bool MatchPayToPubkeyHash256(const CScript& script, valtype& pubkeyhash)
{
    if (!script.IsPayToPublicKeyHash256()) {
        return false;
    }
    pubkeyhash = valtype(script.begin () + 3, script.begin() + 35);
    return true;
}


/** Test for "small positive integer" script opcodes - OP_1 through OP_16. */
static constexpr bool IsSmallInteger(opcodetype opcode)
{
    return opcode >= OP_1 && opcode <= OP_16;
}

static bool MatchMultisig(const CScript& script, unsigned int& required, std::vector<valtype>& pubkeys)
{
    opcodetype opcode;
    valtype data;
    CScript::const_iterator it = script.begin();
    if (script.size() < 1 || script.back() != OP_CHECKMULTISIG) return false;

    if (!script.GetOp(it, opcode, data) || !IsSmallInteger(opcode)) return false;
    required = CScript::DecodeOP_N(opcode);
    while (script.GetOp(it, opcode, data) && CPubKey::ValidSize(data)) {
        pubkeys.emplace_back(std::move(data));
    }
    if (!IsSmallInteger(opcode)) return false;
    unsigned int keys = CScript::DecodeOP_N(opcode);
    if (pubkeys.size() != keys || keys < required) return false;
    return (it + 1 == script.end());
}

TxoutType Solver(const CScript& scriptPubKeyIn, std::vector<std::vector<unsigned char>>& vSolutionsRet)
{
    vSolutionsRet.clear();

    opcodetype opcode;
    std::vector<unsigned char> vch1;
    CScript::const_iterator pc1 = scriptPubKeyIn.begin();
    size_t k;
    for (k = 0; k < 3; ++k) {
        if (!scriptPubKeyIn.GetOp(pc1, opcode, vch1)) {
            break;
        }
        if (k == 0) {
            if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            } else {
                break;
            }
        } else
        if (k == 1) {
            if (opcode != OP_CHECKLOCKTIMEVERIFY
                && opcode != OP_CHECKSEQUENCEVERIFY) {
                break;
            }
        } else
        if (k == 2) {
             if (opcode != OP_DROP) {
                break;
            }
        }
    }
    bool fIsTimeLocked = k == 3;

    CScript scriptPubKeyTemp;
    if (fIsTimeLocked) {
        scriptPubKeyTemp.insert(scriptPubKeyTemp.end(), pc1, scriptPubKeyIn.end());
    }
    const CScript& scriptPubKey = !fIsTimeLocked ? scriptPubKeyIn : scriptPubKeyTemp;

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash()) {
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return fIsTimeLocked ? TxoutType::TIMELOCKED_SCRIPTHASH : TxoutType::SCRIPTHASH;
    }

    if (scriptPubKey.IsPayToScriptHash256()) {
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+34);
        vSolutionsRet.push_back(hashBytes);
        return fIsTimeLocked ? TxoutType::TIMELOCKED_SCRIPTHASH256 : TxoutType::SCRIPTHASH256;
    }

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_KEYHASH_SIZE) {
            vSolutionsRet.push_back(witnessprogram);
            return TxoutType::WITNESS_V0_KEYHASH;
        }
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            vSolutionsRet.push_back(witnessprogram);
            return TxoutType::WITNESS_V0_SCRIPTHASH;
        }
        if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE) {
            vSolutionsRet.push_back(std::vector<unsigned char>{(unsigned char)witnessversion});
            vSolutionsRet.push_back(std::move(witnessprogram));
            return TxoutType::WITNESS_V1_TAPROOT;
        }
        if (witnessversion != 0) {
            vSolutionsRet.push_back(std::vector<unsigned char>{(unsigned char)witnessversion});
            vSolutionsRet.push_back(std::move(witnessprogram));
            return TxoutType::WITNESS_UNKNOWN;
        }
        return TxoutType::NONSTANDARD;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        return TxoutType::NULL_DATA;
    }

    std::vector<unsigned char> data;
    if (MatchPayToPubkey(scriptPubKey, data)) {
        vSolutionsRet.push_back(std::move(data));
        return TxoutType::PUBKEY;
    }

    if (MatchPayToPubkeyHash(scriptPubKey, data)) {
        vSolutionsRet.push_back(std::move(data));
        return fIsTimeLocked ? TxoutType::TIMELOCKED_PUBKEYHASH : TxoutType::PUBKEYHASH;
    }

    if (MatchPayToPubkeyHash256(scriptPubKey, data)) {
        vSolutionsRet.push_back(std::move(data));
        return fIsTimeLocked ? TxoutType::TIMELOCKED_PUBKEYHASH256 : TxoutType::PUBKEYHASH256;
    }

    unsigned int required;
    std::vector<std::vector<unsigned char>> keys;
    if (MatchMultisig(scriptPubKey, required, keys)) {
        vSolutionsRet.push_back({static_cast<unsigned char>(required)}); // safe as required is in range 1..16
        vSolutionsRet.insert(vSolutionsRet.end(), keys.begin(), keys.end());
        vSolutionsRet.push_back({static_cast<unsigned char>(keys.size())}); // safe as size is in range 1..16
        return fIsTimeLocked ? TxoutType::TIMELOCKED_MULTISIG : TxoutType::MULTISIG;
    }

    vSolutionsRet.clear();
    return TxoutType::NONSTANDARD;
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    std::vector<valtype> vSolutions;

    if (HasIsCoinstakeOp(scriptPubKey)) {
        CScript scriptB;
        if (!GetNonCoinstakeScriptPath(scriptPubKey, scriptB))
            return false;

        // Return only the spending address
        return ExtractDestination(scriptB, addressRet);
    }

    TxoutType whichType = Solver(scriptPubKey, vSolutions);

    if (whichType == TxoutType::PUBKEY) {
        CPubKey pubKey(vSolutions[0]);
        if (!pubKey.IsValid())
            return false;

        addressRet = PKHash(pubKey);
        return true;
    }
    else if (whichType == TxoutType::PUBKEYHASH || whichType == TxoutType::TIMELOCKED_PUBKEYHASH)
    {
        addressRet = PKHash(uint160(vSolutions[0]));
        return true;
    }
    else if (whichType == TxoutType::SCRIPTHASH || whichType == TxoutType::TIMELOCKED_SCRIPTHASH)
    {
        addressRet = ScriptHash(uint160(vSolutions[0]));
        return true;
    } else if (whichType == TxoutType::WITNESS_V0_KEYHASH) {
        WitnessV0KeyHash hash;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
        addressRet = hash;
        return true;
    } else if (whichType == TxoutType::WITNESS_V0_SCRIPTHASH) {
        WitnessV0ScriptHash hash;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
        addressRet = hash;
        return true;
    } else if (whichType == TxoutType::WITNESS_UNKNOWN || whichType == TxoutType::WITNESS_V1_TAPROOT) {
        WitnessUnknown unk;
        unk.version = vSolutions[0][0];
        std::copy(vSolutions[1].begin(), vSolutions[1].end(), unk.program);
        unk.length = vSolutions[1].size();
        addressRet = unk;
        return true;
    }
    else if (whichType == TxoutType::PUBKEYHASH256)
    {
        addressRet = CKeyID256(uint256(vSolutions[0]));
        return true;
    }
    else if (whichType == TxoutType::SCRIPTHASH256)
    {
        addressRet = CScriptID256(uint256(vSolutions[0]));
        return true;
    }
    // Multisig txns have more than one address...
    return false;
}

bool ExtractDestinations(const CScript& scriptPubKey, TxoutType& typeRet, std::vector<CTxDestination>& addressRet, int& nRequiredRet)
{
    addressRet.clear();
    std::vector<valtype> vSolutions;

    if (HasIsCoinstakeOp(scriptPubKey)) {
        CScript scriptB;
        if (!GetNonCoinstakeScriptPath(scriptPubKey, scriptB)) {
            typeRet = TxoutType::NONSTANDARD;
            return false;
        }
        // Return only the spending address to keep insight working
        return ExtractDestinations(scriptB, typeRet, addressRet, nRequiredRet);
    }

    typeRet = Solver(scriptPubKey, vSolutions);
    if (typeRet == TxoutType::NONSTANDARD) {
        return false;
    } else if (typeRet == TxoutType::NULL_DATA) {
        // This is data, not addresses
        return false;
    }

    if (typeRet == TxoutType::MULTISIG || typeRet == TxoutType::TIMELOCKED_MULTISIG)
    {
        nRequiredRet = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1; i++)
        {
            CPubKey pubKey(vSolutions[i]);
            if (!pubKey.IsValid())
                continue;

            CTxDestination address = PKHash(pubKey);
            addressRet.push_back(address);
        }

        if (addressRet.empty())
            return false;
    }
    else
    {
        nRequiredRet = 1;
        CTxDestination address;
        if (!ExtractDestination(scriptPubKey, address))
           return false;
        addressRet.push_back(address);
    }

    return true;
}

bool ExtractStakingKeyID(const CScript &scriptPubKey, CKeyID &keyID)
{
    if (scriptPubKey.IsPayToPublicKeyHash()) {
        keyID = CKeyID(uint160(&scriptPubKey[3], 20));
        return true;
    }

    if (scriptPubKey.IsPayToPublicKeyHash256()) {
        keyID = CKeyID(uint256(&scriptPubKey[3], 32));
        return true;
    }

    if (scriptPubKey.IsPayToPublicKeyHash256_CS()
        || scriptPubKey.IsPayToScriptHash256_CS()
        || scriptPubKey.IsPayToScriptHash_CS()) {
        keyID = CKeyID(uint160(&scriptPubKey[5], 20));
        return true;
    }

    return false;
};

namespace
{
class CScriptVisitor : public boost::static_visitor<CScript>
{
public:
    CScript operator()(const CNoDestination& dest) const
    {
        return CScript();
    }

    CScript operator()(const PKHash& keyID) const
    {
        return CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
    }

    CScript operator()(const ScriptHash& scriptID) const
    {
        return CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    }

    CScript operator()(const WitnessV0KeyHash& id) const
    {
        return CScript() << OP_0 << ToByteVector(id);
    }

    CScript operator()(const WitnessV0ScriptHash& id) const
    {
        return CScript() << OP_0 << ToByteVector(id);
    }

    CScript operator()(const WitnessUnknown& id) const
    {
        return CScript() << CScript::EncodeOP_N(id.version) << std::vector<unsigned char>(id.program, id.program + id.length);
    }

    CScript operator()(const CStealthAddress &ek) const {
        return CScript();
    }

    CScript operator()(const CExtPubKey &ek) const {
        return CScript();
    }

    CScript operator()(const CKeyID256 &keyID) const {
        return CScript() << OP_DUP << OP_SHA256 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
    }

    CScript operator()(const CScriptID256 &scriptID) const {
        return CScript() << OP_SHA256 << ToByteVector(scriptID) << OP_EQUAL;
    }
};
} // namespace

CScript GetScriptForDestination(const CTxDestination& dest)
{
    return boost::apply_visitor(CScriptVisitor(), dest);
}

CScript GetScriptForRawPubKey(const CPubKey& pubKey)
{
    return CScript() << std::vector<unsigned char>(pubKey.begin(), pubKey.end()) << OP_CHECKSIG;
}

CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
    CScript script;

    script << CScript::EncodeOP_N(nRequired);
    for (const CPubKey& key : keys)
        script << ToByteVector(key);
    script << CScript::EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
    return script;
}

bool IsValidDestination(const CTxDestination& dest) {
    return dest.which() != 0;
}


TxoutType ToTxoutType(uint8_t type_byte)
{
    switch (type_byte) {
        case 0: return TxoutType::NONSTANDARD;
        case 1: return TxoutType::PUBKEY;
        case 2: return TxoutType::PUBKEYHASH;
        case 3: return TxoutType::SCRIPTHASH;
        case 4: return TxoutType::MULTISIG;
        case 5: return TxoutType::NULL_DATA;
        case 6: return TxoutType::WITNESS_V0_SCRIPTHASH;
        case 7: return TxoutType::WITNESS_V0_KEYHASH;
        case 8: return TxoutType::WITNESS_UNKNOWN;
        case 9: return TxoutType::SCRIPTHASH256;
        case 10: return TxoutType::PUBKEYHASH256;
        case 11: return TxoutType::TIMELOCKED_SCRIPTHASH;
        case 12: return TxoutType::TIMELOCKED_SCRIPTHASH256;
        case 13: return TxoutType::TIMELOCKED_PUBKEYHASH;
        case 14: return TxoutType::TIMELOCKED_PUBKEYHASH256;
        case 15: return TxoutType::TIMELOCKED_MULTISIG;
        case 16: return TxoutType::WITNESS_V1_TAPROOT;
        default: return TxoutType::NONSTANDARD;
    }
}

uint8_t FromTxoutType(TxoutType type_class)
{
    switch (type_class) {
        case TxoutType::NONSTANDARD: return 0;
        case TxoutType::PUBKEY: return 1;
        case TxoutType::PUBKEYHASH: return 2;
        case TxoutType::SCRIPTHASH: return 3;
        case TxoutType::MULTISIG: return 4;
        case TxoutType::NULL_DATA: return 5;
        case TxoutType::WITNESS_V0_SCRIPTHASH: return 6;
        case TxoutType::WITNESS_V0_KEYHASH: return 7;
        case TxoutType::WITNESS_UNKNOWN: return 8;
        case TxoutType::SCRIPTHASH256: return 9;
        case TxoutType::PUBKEYHASH256: return 10;
        case TxoutType::TIMELOCKED_SCRIPTHASH: return 11;
        case TxoutType::TIMELOCKED_SCRIPTHASH256: return 12;
        case TxoutType::TIMELOCKED_PUBKEYHASH: return 13;
        case TxoutType::TIMELOCKED_PUBKEYHASH256: return 14;
        case TxoutType::TIMELOCKED_MULTISIG: return 15;
        case TxoutType::WITNESS_V1_TAPROOT: return 16;
    }
    return 0;
}
