// Copyright (c) 2018-2020 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_USBDEVICE_LEDGERDEVICE_H
#define PARTICL_USBDEVICE_LEDGERDEVICE_H

#include <usbdevice/usbdevice.h>

struct hid_device_;
typedef struct hid_device_ hid_device;

namespace usb_device {

class CLedgerDevice : public CUSBDevice
{
public:
    CLedgerDevice(const DeviceType *pType_, const char *cPath_, const char *cSerialNo_, int nInterface_)
        : CUSBDevice(pType_, cPath_, cSerialNo_, nInterface_) {};

    int Open() override;
    int Close() override;

    int GetFirmwareVersion(std::string &sFirmware, std::string &sError) override;
    int GetInfo(UniValue &info, std::string &sError) override;

    int GetPubKey(const std::vector<uint32_t> &vPath, CPubKey &pk, bool display, std::string &sError) override;
    int GetXPub(const std::vector<uint32_t> &vPath, CExtPubKey &ekp, std::string &sError) override;

    int SignMessage(const std::vector<uint32_t> &vPath, const std::string &sMessage, std::vector<uint8_t> &vchSig, std::string &sError) override;

    int PrepareTransaction(CMutableTransaction &tx, const CCoinsViewCache &view, const FillableSigningProvider &keystore, int nHashType,
                           int change_pos, const std::vector<uint32_t> &change_path) override;

    int SignTransaction(const std::vector<uint32_t> &vPath, const std::vector<uint8_t> &vSharedSecret, const CMutableTransaction *tx,
        int nIn, const CScript &scriptCode, int hashType, const std::vector<uint8_t> &amount, SigVersion sigversion,
        std::vector<uint8_t> &vchSig, std::string &sError) override;

protected:
    hid_device *handle = nullptr;
};

} // usb_device

#endif // PARTICL_USBDEVICE_LEDGERDEVICE_H
