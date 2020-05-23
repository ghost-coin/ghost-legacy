// Copyright (c) 2014 The ShadowCoin developers
// Copyright (c) 2017-2020 The Particl Core developers
// Copyright (c) 2020 The Ghost Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_KEY_STEALTH_H
#define GHOST_KEY_STEALTH_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

#include <key.h>
#include <key/types.h>

class CScript;

const uint32_t MAX_STEALTH_NARRATION_SIZE = 48;
const uint32_t MIN_STEALTH_RAW_SIZE = 1 + 33 + 1 + 33 + 1 + 1; // without checksum (4bytes) or version (1byte)
const size_t MAX_STEALTH_PREFIX_BYTES = 4;
const size_t MAX_STEALTH_SPEND_KEYS = 255;
const size_t MAX_STEALTH_RAW_SIZE = MIN_STEALTH_RAW_SIZE + EC_COMPRESSED_SIZE * (MAX_STEALTH_SPEND_KEYS-1) + MAX_STEALTH_PREFIX_BYTES;

typedef uint32_t stealth_bitfield;

struct stealth_prefix
{
    uint8_t number_bits;
    stealth_bitfield bitfield;
};

class CStealthAddress
{
public:
    CStealthAddress()
    {
        options = 0;
        number_signatures = 0;
        prefix.number_bits = 0;

        //index = 0;
    };

    uint8_t options;
    stealth_prefix prefix;
    int number_signatures;
    ec_point scan_pubkey;
    ec_point spend_pubkey;

    mutable std::string label;

    CKey scan_secret;       // Better to store the scan secret here as it's needed often
    CKeyID spend_secret_id; // store the spend secret in a keystore
    //CKey spend_secret;
    //uint32_t index;

    bool SetEncoded(const std::string &encodedAddress);
    std::string Encoded(bool fBech32=false) const;
    std::string ToString(bool fBech32=false) const {return Encoded(fBech32);};

    int FromRaw(const uint8_t *p, size_t nSize);
    int ToRaw(std::vector<uint8_t> &raw) const;

    int SetScanPubKey(CPubKey pk);

    CKeyID GetScanKeyID() const;
    CKeyID GetSpendKeyID() const;

    bool operator <(const CStealthAddress &y) const
    {
        return memcmp(&scan_pubkey[0], &y.scan_pubkey[0], EC_COMPRESSED_SIZE) < 0;
    }

    bool operator ==(const CStealthAddress &y) const
    {
        return memcmp(&scan_pubkey[0], &y.scan_pubkey[0], EC_COMPRESSED_SIZE) == 0;
    }

    template<typename Stream>
    void Serialize(Stream &s) const
    {
        s << options;

        s << number_signatures;
        s << prefix.number_bits;
        s << prefix.bitfield;

        s << scan_pubkey;
        s << spend_pubkey;
        s << label;

        bool fHaveScanSecret = scan_secret.IsValid();
        s << fHaveScanSecret;
        if (fHaveScanSecret) {
            s.write((char*)scan_secret.begin(), EC_SECRET_SIZE);
        }
    }
    template <typename Stream>
    void Unserialize(Stream &s)
    {
        s >> options;

        s >> number_signatures;
        s >> prefix.number_bits;
        s >> prefix.bitfield;

        s >> scan_pubkey;
        s >> spend_pubkey;
        s >> label;

        bool fHaveScanSecret;
        s >> fHaveScanSecret;

        if (fHaveScanSecret) {
            s.read((char*)scan_secret.begin(), EC_SECRET_SIZE);
            scan_secret.SetFlags(true, true);

            // Only derive spend_secret_id if also have the scan secret.
            if (spend_pubkey.size() == EC_COMPRESSED_SIZE) { // TODO: won't work for multiple spend pubkeys
                spend_secret_id = GetSpendKeyID();
            }
        }
    }
};

int SecretToPublicKey(const CKey &secret, ec_point &out);
int SetPublicKey(const CPubKey &pk, ec_point &out);

int StealthShared(const CKey &secret, const ec_point &pubkey, CKey &sharedSOut);
int StealthSecret(const CKey &secret, const ec_point &pubkey, const ec_point &pkSpend, CKey &sharedSOut, ec_point &pkOut);
int StealthSecretSpend(const CKey &scanSecret, const ec_point &ephemPubkey, const CKey &spendSecret, CKey &secretOut);
int StealthSharedToSecretSpend(const CKey &sharedS, const CKey &spendSecret, CKey &secretOut);

int StealthSharedToPublicKey(const ec_point &pkSpend, const CKey &sharedS, ec_point &pkOut);

bool IsStealthAddress(const std::string &encodedAddress);

inline uint32_t SetStealthMask(uint8_t nBits)
{
    return (nBits == 32 ? 0xFFFFFFFF : ((1<<nBits)-1));
};

uint32_t FillStealthPrefix(uint8_t nBits, uint32_t nBitfield);

bool ExtractStealthPrefix(const char *pPrefix, uint32_t &nPrefix);

int MakeStealthData(const std::string &sNarration, stealth_prefix prefix, const CKey &sShared, const CPubKey &pkEphem,
    std::vector<uint8_t> &vData, uint32_t &nStealthPrefix, std::string &sError);

int PrepareStealthOutput(const CStealthAddress &sx, const std::string &sNarration,
    CScript &scriptPubKey, std::vector<uint8_t> &vData, std::string &sError);

void ECC_Start_Stealth();
void ECC_Stop_Stealth();


#endif  // GHOST_KEY_STEALTH_H

