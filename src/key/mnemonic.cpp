// Copyright (c) 2014-2015 The ShadowCoin developers
// Copyright (c) 2017-2020 The Particl Core developers
// Copyright (c) 2020 The Ghost Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#define ENABLE_BIP39_ENGLISH 1
#define ENABLE_BIP39_FRENCH 1
#define ENABLE_BIP39_JAPANESE 1
#define ENABLE_BIP39_SPANISH 1
#define ENABLE_BIP39_CHINESE_S 1
#define ENABLE_BIP39_CHINESE_T 1
#define ENABLE_BIP39_ITALIAN 1
#define ENABLE_BIP39_KOREAN 1
#define ENABLE_BIP39_CZECH 1

#include <key/mnemonic.h>

#include <util/system.h>
#include <util/string.h>
#include <crypto/hmac_sha512.h>
#include <crypto/sha256.h>

#include <unilib/uninorms.h>
#include <unilib/utf8.h>

#ifdef ENABLE_BIP39_ENGLISH
#include <key/wordlists/english.h>
#else
unsigned char *english_txt = nullptr;
uint32_t english_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_FRENCH
#include <key/wordlists/french.h>
#else
unsigned char *french_txt = nullptr;
uint32_t french_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_JAPANESE
#include <key/wordlists/japanese.h>
#else
unsigned char *japanese_txt = nullptr;
uint32_t japanese_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_SPANISH
#include <key/wordlists/spanish.h>
#else
unsigned char *spanish_txt = nullptr;
uint32_t spanish_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_CHINESE_S
#include <key/wordlists/chinese_simplified.h>
#else
unsigned char *chinese_simplified_txt = nullptr;
uint32_t chinese_simplified_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_CHINESE_T
#include <key/wordlists/chinese_traditional.h>
#else
unsigned char *chinese_traditional_txt = nullptr;
uint32_t chinese_traditional_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_ITALIAN
#include <key/wordlists/italian.h>
#else
unsigned char *italian_txt = nullptr;
uint32_t italian_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_KOREAN
#include <key/wordlists/korean.h>
#else
unsigned char *korean_txt = nullptr;
uint32_t korean_txt_len = 0;
#endif
#ifdef ENABLE_BIP39_CZECH
#include <key/wordlists/czech.h>
#else
unsigned char *czech_txt = nullptr;
uint32_t czech_txt_len = 0;
#endif

namespace mnemonic {

static const unsigned char *mnLanguages[] =
{
    nullptr,
    english_txt,
    french_txt,
    japanese_txt,
    spanish_txt,
    chinese_simplified_txt,
    chinese_traditional_txt,
    italian_txt,
    korean_txt,
    czech_txt,
};

static const uint32_t mnLanguageLens[] =
{
    0,
    english_txt_len,
    french_txt_len,
    japanese_txt_len,
    spanish_txt_len,
    chinese_simplified_txt_len,
    chinese_traditional_txt_len,
    italian_txt_len,
    korean_txt_len,
    czech_txt_len,
};

const char *mnLanguagesDesc[WLL_MAX] =
{
    nullptr,
    "English",
    "French",
    "Japanese",
    "Spanish",
    "Chinese Simplified",
    "Chinese Traditional",
    "Italian",
    "Korean",
    "Czech",
};

const char *mnLanguagesTag[WLL_MAX] =
{
    nullptr,
    "english",
    "french",
    "japanese",
    "spanish",
    "chinese_s",
    "chinese_t",
    "italian",
    "korean",
    "czech",
};

static void NormaliseUnicode(std::string &str)
{
    if (str.size() < 1) {
        return;
    }
    std::u32string u32;
    ufal::unilib::utf8::decode(str, u32);
    ufal::unilib::uninorms::nfkd(u32);
    ufal::unilib::utf8::encode(u32, str);
};

static void NormaliseInput(std::string &str)
{
    part::TrimWhitespace(str);
    NormaliseUnicode(str);
};

int GetWord(int o, const char *pwl, int max, std::string &sWord)
{
    sWord = "";
    char *pt = (char*)pwl;
    while (o > 0) {
        if (*pt == '\n') {
            o--;
        }
        pt++;

        if (pt >= pwl+max) {
            return 1;
        }
    }

    while (pt < (pwl+max)) {
        if (*pt == '\n') {
            return 0;
        }
        sWord += *pt;
        pt++;
    }

    return 1;
};

int GetWordOffset(const char *p, const char *pwl, int max, int &o)
{
    // List must end with \n
    char *pt = (char*)pwl;
    int l = strlen(p);
    int i = 0;
    int c = 0;
    int f = 1;
    while (pt < (pwl+max)) {
        if (*pt == '\n') {
            if (f && c == l) { // found
                o = i;
                return 0;
            }
            i++;
            c = 0;
            f = 1;
        } else {
            if (c >= l) {
                f = 0;
            } else
            if (f && *(p+c) != *pt) {
                f = 0;
            }
            c++;
        }
        pt++;
    }
    return 1;
};

int GetLanguageOffset(std::string sIn)
{
    int nLanguage = -1;
    std::transform(sIn.begin(), sIn.end(), sIn.begin(), ::tolower);

    for (size_t k = 1; k < WLL_MAX; ++k) {
        if (sIn != mnLanguagesTag[k]) {
            continue;
        }
        nLanguage = k;
        break;
    }

    if (nLanguage < 1 || nLanguage >= WLL_MAX || !HaveLanguage(nLanguage)) {
        throw std::runtime_error("Unknown language.");
    }

    return nLanguage;
};

int DetectLanguage(const std::string &sWordList)
{
    // Try detect the language
    // Tolerate spelling mistakes, will be reported in other functions
    char tmp[2048];
    if (sWordList.size() >= 2048) {
        return errorN(-1, "%s: Word List too long.", __func__);
    }

    for (int l = 1; l < WLL_MAX; ++l) {
        char *pwl = (char*) mnLanguages[l];
        if (!pwl) {
            continue;
        }
        int m = mnLanguageLens[l];
        strcpy(tmp, sWordList.c_str());

        // The Chinese dialects have many words in common, match full phrase
        int maxTries = (l == WLL_CHINESE_S || l == WLL_CHINESE_T) ? 24 : 8;

        int nHit = 0;
        int nMiss = 0;
        char *p, *token;
        p = strtok_r(tmp, " ", &token);
        while (p != nullptr) {
            int ofs;
            if (0 == GetWordOffset(p, pwl, m, ofs)) {
                nHit++;
            } else {
                nMiss++;
            }

            if (!maxTries--) {
                break;
            }
            p = strtok_r(nullptr, " ", &token);
        }

        // Chinese dialects overlap too much to tolerate failures
        if ((l == WLL_CHINESE_S || l == WLL_CHINESE_T)
            && nMiss > 0) {
            continue;
        }

        if (nHit > nMiss && nMiss < 2) { // tolerate max 2 failures
            return l;
        }
    }

    return 0;
};

int Encode(int nLanguage, const std::vector<uint8_t> &vEntropy, std::string &sWordList, std::string &sError)
{
    LogPrint(BCLog::HDWALLET, "%s: language %d.\n", __func__, nLanguage);

    sWordList = "";

    if (nLanguage < 1 || nLanguage >= WLL_MAX || !mnLanguages[nLanguage]) {
        sError = "Unknown language.";
        return errorN(1, "%s: %s", __func__, sError.c_str());
    }

    // Checksum is 1st n bytes of the sha256 hash
    uint8_t hash[32];
    CSHA256().Write(&vEntropy[0], vEntropy.size()).Finalize((uint8_t*)hash);

    int nCsSize = vEntropy.size() / 4; // 32 / 8
    if (nCsSize < 1 || nCsSize > 256) {
        sError = "Entropy bytes out of range.";
        return errorN(2, "%s: %s", __func__, sError.c_str());
    }

    std::vector<uint8_t> vIn = vEntropy;

    int ncb = nCsSize/8;
    int r = nCsSize % 8;
    if (r != 0) {
        ncb++;
    }
    std::vector<uint8_t> vTmp(32);
    memcpy(&vTmp[0], &hash, ncb);
    memset(&vTmp[ncb], 0, 32-ncb);

    vIn.insert(vIn.end(), vTmp.begin(), vTmp.end());

    std::vector<int> vWord;

    int nBits = vEntropy.size() * 8 + nCsSize;

    int i = 0;
    while (i < nBits) {
        int o = 0;
        int s = i / 8;
        int r = i % 8;

        uint8_t b1 = vIn[s];
        uint8_t b2 = vIn[s+1];

        o = (b1 << r) & 0xFF;
        o = o << (11 - 8);

        if (r > 5) {
            uint8_t b3 = vIn[s+2];
            o |= (b2 << (r-5));
            o |= (b3 >> (8-(r-5)));
        } else {
            o |= ((int)b2) >> ((8 - (11 - 8))-r);
        }

        o = o & 0x7FF;

        vWord.push_back(o);
        i += 11;
    }

    char *pwl = (char*) mnLanguages[nLanguage];
    int m = mnLanguageLens[nLanguage];

    for (size_t k = 0; k < vWord.size(); ++k) {
        int o = vWord[k];

        std::string sWord;
        if (0 != GetWord(o, pwl, m, sWord)) {
            sError = strprintf("Word extract failed %d, language %d.", o, nLanguage);
            return errorN(3, "%s: %s", __func__, sError.c_str());
        }

        if (sWordList != "") {
            sWordList += " ";
        }
        sWordList += sWord;
    }

    if (nLanguage == WLL_JAPANESE) {
        part::ReplaceStrInPlace(sWordList, " ", "\u3000");
    }

    return 0;
};

int Decode(int &nLanguage, const std::string &sWordListIn, std::vector<uint8_t> &vEntropy, std::string &sError, bool fIgnoreChecksum)
{
    LogPrint(BCLog::HDWALLET, "%s: Language %d.\n", __func__, nLanguage);

    std::string sWordList = sWordListIn;
    NormaliseInput(sWordList);

    if (nLanguage == -1) {
        nLanguage = DetectLanguage(sWordList);
    }

    if (nLanguage < 1 || nLanguage >= WLL_MAX || !mnLanguages[nLanguage]) {
        sError = "Unknown language";
        return errorN(1, "%s: %s", __func__, sError.c_str());
    }

    LogPrint(BCLog::HDWALLET, "%s: Detected language %d.\n", __func__, nLanguage);

    char tmp[2048];
    if (sWordList.size() >= 2048) {
        sError = "Word List too long.";
        return errorN(2, "%s: %s", __func__, sError.c_str());
    }

    if (strstr(sWordList.c_str(), "  ") != NULL) {
        sError = "Multiple spaces between words";
        return errorN(4, "%s: %s", __func__, sError.c_str());
    }

    strcpy(tmp, sWordList.c_str());

    char *pwl = (char*) mnLanguages[nLanguage];
    int m = mnLanguageLens[nLanguage];

    std::vector<int> vWordInts;

    char *p, *token;
    p = strtok_r(tmp, " ", &token);
    while (p != nullptr) {
        int ofs;
        if (0 != GetWordOffset(p, pwl, m, ofs)) {
            sError = strprintf("Unknown word: %s", p);
            return errorN(3, "%s: %s", __func__, sError.c_str());
        }

        vWordInts.push_back(ofs);
        p = strtok_r(nullptr, " ", &token);
    }

    if (!fIgnoreChecksum
        && vWordInts.size() % 3 != 0) {
        sError = "No. of words must be divisible by 3";
        return errorN(4, "%s: %s", __func__, sError.c_str());
    }

    int nBits = vWordInts.size() * 11;
    int nBytes = nBits/8 + (nBits % 8 == 0 ? 0 : 1);
    vEntropy.resize(nBytes);

    memset(&vEntropy[0], 0, nBytes);

    int i = 0;
    size_t wl = vWordInts.size();
    size_t el = vEntropy.size();
    for (size_t k = 0; k < wl; ++k) {
        int o = vWordInts[k];

        int s = i / 8;
        int r = i % 8;

        vEntropy[s] |= (o >> (r+3)) & 0x7FF;

        if (s < (int)el-1) {
            if (r > 5) {
                vEntropy[s+1] |= (uint8_t) ((o >> (r-5))) & 0x7FF;
                if (s < (int)el-2) {
                    vEntropy[s+2] |= (uint8_t) (o << (8-(r-5))) & 0x7FF;
                }
            } else {
                vEntropy[s+1] |= (uint8_t) (o << (5-r)) & 0x7FF;
            }
        }
        i += 11;
    }

    if (fIgnoreChecksum) {
        return 0;
    }

    // Checksum
    int nLenChecksum = nBits / 32;
    int nLenEntropy = nBits - nLenChecksum;

    int nBytesEntropy = nLenEntropy / 8;
    int nBytesChecksum = nLenChecksum / 8 + (nLenChecksum % 8 == 0 ? 0 : 1);

    std::vector<uint8_t> vCS;

    vCS.resize(nBytesChecksum);
    memcpy(&vCS[0], &vEntropy[nBytesEntropy], nBytesChecksum);

    vEntropy.resize(nBytesEntropy);

    uint8_t hash[32];
    CSHA256().Write(&vEntropy[0], vEntropy.size()).Finalize((uint8_t*)hash);

    std::vector<uint8_t> vCSTest;

    vCSTest.resize(nBytesChecksum);
    memcpy(&vCSTest[0], &hash, nBytesChecksum);

    int r = nLenChecksum % 8;

    if (r > 0) {
        vCSTest[nBytesChecksum-1] &= (((1<<r)-1) << (8-r));
    }

    if (vCSTest != vCS) {
        sError = "Checksum mismatch.";
        return errorN(5, "%s: %s", __func__, sError.c_str());
    }

    return 0;
};

static int mnemonicKdf(const uint8_t *password, size_t lenPassword,
    const uint8_t *salt, size_t lenSalt, size_t nIterations, uint8_t *out)
{
    /*
    https://tools.ietf.org/html/rfc2898
    5.2 PBKDF2

    F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
    where
        U_1 = PRF (P, S || INT (i)) ,
        U_2 = PRF (P, U_1) ,
        ...
        U_c = PRF (P, U_{c-1}) .
    */

    // Output length is always 64bytes, only 1 block

    if (nIterations < 1) {
        return 1;
    }

    uint8_t r[64];

    int one = 0x01000000;
    CHMAC_SHA512 ctx(password, lenPassword);
    CHMAC_SHA512 ctx_state = ctx;
    ctx.Write(salt, lenSalt);
    ctx.Write((uint8_t*)&one, 4);
    ctx.Finalize(r);
    memcpy(out, r, 64);

    for (size_t k = 1; k < nIterations; ++k) {
        ctx= ctx_state;
        ctx.Write(r, 64);
        ctx.Finalize(r);

        for (size_t i = 0; i < 64; ++i) {
            out[i] ^= r[i];
        }
    }

    return 0;
};

int ToSeed(const std::string &sMnemonic, const std::string &sPasswordIn, std::vector<uint8_t> &vSeed)
{
    LogPrint(BCLog::HDWALLET, "%s\n", __func__);

    vSeed.resize(64);

    std::string sWordList = sMnemonic;
    NormaliseInput(sWordList);

    std::string sPassword = sPasswordIn;
    NormaliseInput(sPassword);

    if (strstr(sWordList.c_str(), "  ") != NULL) {
        return errorN(1, "%s: Multiple spaces between words.", __func__);
    }

    int nIterations = 2048;

    std::string sSalt = std::string("mnemonic") + sPassword;

    if (0 != mnemonicKdf((uint8_t*)sWordList.data(), sWordList.size(),
        (uint8_t*)sSalt.data(), sSalt.size(), nIterations, &vSeed[0])) {
        return errorN(1, "%s: mnemonicKdf failed.", __func__);
    }

    return 0;
};

int AddChecksum(int nLanguageIn, const std::string &sWordListIn, std::string &sWordListOut, std::string &sError)
{
    std::string sWordList = sWordListIn;
    NormaliseInput(sWordList);

    sWordListOut = "";
    int nLanguage = nLanguageIn;
    if (nLanguage == -1) {
        nLanguage = DetectLanguage(sWordList); // Needed here for MnemonicEncode, MnemonicDecode will complain if in error
    }

    int rv;
    std::vector<uint8_t> vEntropy;
    if (0 != (rv = Decode(nLanguage, sWordList, vEntropy, sError, true))) {
        return rv;
    }

    if (0 != (rv = Encode(nLanguage, vEntropy, sWordListOut, sError))) {
        return rv;
    }

    if (0 != (rv = Decode(nLanguage, sWordListOut, vEntropy, sError))) {
        return rv;
    }

    return 0;
};

int GetWord(int nLanguage, int nWord, std::string &sWord, std::string &sError)
{
    if (nLanguage < 1 || nLanguage >= WLL_MAX || !mnLanguages[nLanguage]) {
        sError = "Unknown language.";
        return errorN(1, "%s: %s", __func__, sError.c_str());
    }

    char *pwl = (char*) mnLanguages[nLanguage];
    int m = mnLanguageLens[nLanguage];

    if (0 != GetWord(nWord, pwl, m, sWord)) {
        sError = strprintf("Word extract failed %d, language %d.", nWord, nLanguage);
        return errorN(3, "%s: %s", __func__, sError.c_str());
    }

    return 0;
};

std::string GetLanguage(int nLanguage)
{
    if (nLanguage < 1 || nLanguage >= WLL_MAX || !mnLanguages[nLanguage]) {
        return "Unknown";
    }

    return mnLanguagesDesc[nLanguage];
};

std::string ListEnabledLanguages(std::string separator)
{
    std::string enabled_languages;
    for (size_t k = 1; k < WLL_MAX; ++k) {
        if (!HaveLanguage(k)) {
            continue;
        }
        if (enabled_languages.size()) {
            enabled_languages += separator;
        }
        enabled_languages += mnLanguagesTag[k];
    }
    return enabled_languages;
};

bool HaveLanguage(int nLanguage){
    return mnLanguages[nLanguage];
}

}
