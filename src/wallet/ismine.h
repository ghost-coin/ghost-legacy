// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_ISMINE_H
#define BITCOIN_WALLET_ISMINE_H

#include <script/standard.h>
#include <script/ismine.h>

#include <stdint.h>
#include <bitset>

class CWallet;
class CScript;

/** IsMine() return codes
enum isminetype : uint8_t
{
    ISMINE_NO               = 0,
    ISMINE_WATCH_ONLY_      = 1 << 0,
    ISMINE_SPENDABLE        = 1 << 1,
    ISMINE_USED             = 1 << 2,
    ISMINE_HARDWARE_DEVICE  = 1 << 6, // Private key is on external device
    ISMINE_WATCH_COLDSTAKE  = 1 << 7,
    ISMINE_WATCH_ONLY       = ISMINE_WATCH_ONLY_ | ISMINE_WATCH_COLDSTAKE,
    ISMINE_ALL              = ISMINE_WATCH_ONLY | ISMINE_SPENDABLE,
    ISMINE_ALL_USED         = ISMINE_ALL | ISMINE_USED,
    ISMINE_ENUM_ELEMENTS,
};
*/
/** used for bitflags of isminetype */
typedef uint8_t isminefilter;

typedef std::vector<unsigned char> valtype;
bool HaveKeys(const std::vector<valtype>& pubkeys, const CWallet& keystore);

/* isInvalid becomes true when the script is found invalid by consensus or policy. This will terminate the recursion
 * and return ISMINE_NO immediately, as an invalid script should never be considered as "mine". This is needed as
 * different SIGVERSION may have different network rules. Currently the only use of isInvalid is indicate uncompressed
 * keys in SigVersion::WITNESS_V0 script, but could also be used in similar cases in the future
 */
isminetype IsMine(const CWallet& keystore, const CScript& scriptPubKey, bool& isInvalid);
isminetype IsMine(const CWallet& keystore, const CScript& scriptPubKey);
isminetype IsMine(const CWallet& keystore, const CTxDestination& dest);
isminetype IsMineP2SH(const CWallet& keystore, const CScript& scriptPubKey);

/**
 * Cachable amount subdivided into watchonly and spendable parts.
 */
struct CachableAmount
{
    // NO and ALL are never (supposed to be) cached
    std::bitset<ISMINE_ENUM_ELEMENTS> m_cached;
    CAmount m_value[ISMINE_ENUM_ELEMENTS];
    inline void Reset()
    {
        m_cached.reset();
    }
    void Set(isminefilter filter, CAmount value)
    {
        m_cached.set(filter);
        m_value[filter] = value;
    }
};

#endif // BITCOIN_WALLET_ISMINE_H
