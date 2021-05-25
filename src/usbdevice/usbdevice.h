// Copyright (c) 2018-2020 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_USBDEVICE_USBDEVICE_H
#define PARTICL_USBDEVICE_USBDEVICE_H

#include <string.h>
#include <assert.h>
#include <vector>
#include <string>

#include <pubkey.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <memory>

struct CExtPubKey;
class UniValue;
class CCoinsViewCache;

namespace usb_device {

enum DeviceTypeID {
    USBDEVICE_UNKNOWN = -1,
    USBDEVICE_DEBUG = 0,
    USBDEVICE_LEDGER_NANO_S = 1,
    USBDEVICE_TREZOR_ONE = 2,
    USBDEVICE_LEDGER_BLUE = 3,
    USBDEVICE_LEDGER_NANO_X = 4,
    USBDEVICE_SIZE,
};

void ShutdownHardwareIntegration();

class CPathKey
{
public:
    std::vector<uint32_t> vPath;
    CPubKey pk;
};

class CPathKeyStore : public FillableSigningProvider
{
public:
    std::map<CKeyID, CPathKey> mapPathKeys;

    using FillableSigningProvider::AddKey;
    bool AddKey(const CPathKey &pathkey)
    {
        LOCK(cs_KeyStore);
        mapPathKeys[pathkey.pk.GetID()] = pathkey;
        return true;
    }

    using FillableSigningProvider::GetKey;
    bool GetKey(const CKeyID &address, CPathKey &keyOut) const
    {
        LOCK(cs_KeyStore);
        std::map<CKeyID, CPathKey>::const_iterator mi = mapPathKeys.find(address);
        if (mi != mapPathKeys.end()) {
            keyOut = mi->second;
            return true;
        }
        return false;
    }
    bool GetPubKey(const CKeyID &address, CPubKey &pkOut) const override
    {
        LOCK(cs_KeyStore);
        std::map<CKeyID, CPathKey>::const_iterator mi = mapPathKeys.find(address);
        if (mi != mapPathKeys.end()) {
            pkOut = mi->second.pk;
            return true;
        }
        return false;
    }
};

class DeviceType
{
public:
    DeviceType(
        int nVendorId_, int nProductId_,
        const char *cVendor_, const char *cProduct_,
        DeviceTypeID type_)
        : nVendorId(nVendorId_), nProductId(nProductId_),
          cVendor(cVendor_), cProduct(cProduct_), type(type_)
        {};

    int nVendorId = 0;
    int nProductId = 0;
    const char *cVendor = nullptr;
    const char *cProduct = nullptr;
    DeviceTypeID type = USBDEVICE_UNKNOWN;
};

extern const DeviceType usbDeviceTypes[];

class CUSBDevice
{
public:
    CUSBDevice() {};
    virtual ~CUSBDevice() {};
    CUSBDevice(const DeviceType *pType_, const char *cPath_, const char *cSerialNo_, int nInterface_) : pType(pType_)
    {
        assert(strlen(cPath_) < sizeof(cPath));
        strcpy(cPath, cPath_);

        cSerialNo[0] = '\n';
        if (cSerialNo_) {
            assert(strlen(cSerialNo_) < sizeof(cSerialNo));
            strcpy(cSerialNo, cSerialNo_);
        }

        nInterface = nInterface_;
    };

    virtual int Open() { return 0; };
    virtual int Close() { return 0; };

    virtual int GetFirmwareVersion(std::string &sFirmware, std::string &sError);
    virtual int GetInfo(UniValue &info, std::string &sError);

    virtual int GetPubKey(const std::vector<uint32_t> &vPath, CPubKey &pk, bool display, std::string &sError) { return 0; };
    virtual int GetXPub(const std::vector<uint32_t> &vPath, CExtPubKey &ekp, std::string &sError) { return 0; };

    virtual int SignMessage(const std::vector<uint32_t> &vPath, const std::string &sMessage, std::vector<uint8_t> &vchSig, std::string &sError) { return 0; };

    virtual int PrepareTransaction(CMutableTransaction &tx, const CCoinsViewCache &view, const FillableSigningProvider &keystore, int nHashType,
                                   int change_pos, const std::vector<uint32_t> &change_path) { return 0; };

    //int SignHash(const std::vector<uint32_t> &vPath, const uint256 &hash, std::vector<uint8_t> &vchSig, std::string &sError);
    virtual int SignTransaction(const std::vector<uint32_t> &vPath, const std::vector<uint8_t> &vSharedSecret, const CMutableTransaction *tx,
        int nIn, const CScript &scriptCode, int hashType, const std::vector<uint8_t> &amount, SigVersion sigversion,
        std::vector<uint8_t> &vchSig, std::string &sError) { return 0; };

    virtual int LoadMnemonic(uint32_t wordcount, bool pinprotection, std::string &sError) { return 0; };
    virtual int Backup(std::string &sError) { return 0; };

    virtual int OpenIfUnlocked(std::string &sError) { return 0; }
    virtual int PromptUnlock(std::string &sError) { return 0; }
    virtual int Unlock(std::string pin, std::string passphraseword, std::string &sError) { return 0; };
    virtual int GenericUnlock(std::vector<uint8_t>* msg_in, uint16_t msg_type_in) { return 0; };

    const DeviceType *pType = nullptr;
    char cPath[512];
    char cSerialNo[128];
    int nInterface;
    std::string sError;
};


void ListHIDDevices(std::vector<std::unique_ptr<CUSBDevice> > &vDevices);
void ListWebUSBDevices(std::vector<std::unique_ptr<CUSBDevice> > &vDevices);
void ListAllDevices(std::vector<std::unique_ptr<CUSBDevice> > &vDevices);
CUSBDevice *SelectDevice(std::vector<std::unique_ptr<CUSBDevice> > &vDevices, std::string &sError);

/** A signature creator for transactions. */
class DeviceSignatureCreator : public BaseSignatureCreator {
    const CMutableTransaction* txTo;
    unsigned int nIn;
    int nHashType;
    std::vector<uint8_t> amount;
    const MutableTransactionSignatureChecker checker;
    CUSBDevice *pDevice;

public:
    DeviceSignatureCreator(CUSBDevice *pDeviceIn, const CMutableTransaction *txToIn, unsigned int nInIn, const std::vector<uint8_t> &amountIn, int nHashTypeIn=SIGHASH_ALL);
    const BaseSignatureChecker &Checker() const override { return checker; }

    bool IsGhostVersion() const override { return txTo && txTo->IsGhostVersion(); }
    bool IsCoinStake() const override { return txTo && txTo->IsCoinStake(); }

    bool CreateSig(const SigningProvider& provider, std::vector<unsigned char> &vchSig, const CKeyID &keyid, const CScript &scriptCode, SigVersion sigversion) const override;
};

} // usb_device

#endif // PARTICL_USBDEVICE_USBDEVICE_H

