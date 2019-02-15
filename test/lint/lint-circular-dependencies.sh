#!/usr/bin/env bash
#
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check for circular dependencies

export LC_ALL=C

EXPECTED_CIRCULAR_DEPENDENCIES=(
    "chainparamsbase -> util/system -> chainparamsbase"
    "checkpoints -> validation -> checkpoints"
    "index/txindex -> validation -> index/txindex"
    "policy/fees -> txmempool -> policy/fees"
    "policy/policy -> validation -> policy/policy"
    "qt/addresstablemodel -> qt/walletmodel -> qt/addresstablemodel"
    "qt/bantablemodel -> qt/clientmodel -> qt/bantablemodel"
    "qt/bitcoingui -> qt/utilitydialog -> qt/bitcoingui"
    "qt/bitcoingui -> qt/walletframe -> qt/bitcoingui"
    "qt/bitcoingui -> qt/walletview -> qt/bitcoingui"
    "qt/clientmodel -> qt/peertablemodel -> qt/clientmodel"
    "qt/paymentserver -> qt/walletmodel -> qt/paymentserver"
    "qt/recentrequeststablemodel -> qt/walletmodel -> qt/recentrequeststablemodel"
    "qt/sendcoinsdialog -> qt/walletmodel -> qt/sendcoinsdialog"
    "qt/transactiontablemodel -> qt/walletmodel -> qt/transactiontablemodel"
    "qt/walletmodel -> qt/walletmodeltransaction -> qt/walletmodel"
    "txmempool -> validation -> txmempool"
    "validation -> validationinterface -> validation"
    "wallet/coincontrol -> wallet/wallet -> wallet/coincontrol"
    "wallet/fees -> wallet/wallet -> wallet/fees"
    "wallet/wallet -> wallet/walletdb -> wallet/wallet"
    "policy/fees -> policy/policy -> validation -> policy/fees"
    "policy/rbf -> txmempool -> validation -> policy/rbf"
    "qt/addressbookpage -> qt/bitcoingui -> qt/walletview -> qt/addressbookpage"
    "qt/guiutil -> qt/walletmodel -> qt/optionsmodel -> qt/guiutil"
    "txmempool -> validation -> validationinterface -> txmempool"
    "qt/addressbookpage -> qt/bitcoingui -> qt/walletview -> qt/receivecoinsdialog -> qt/addressbookpage"
    "qt/addressbookpage -> qt/bitcoingui -> qt/walletview -> qt/signverifymessagedialog -> qt/addressbookpage"
    "qt/guiutil -> qt/walletmodel -> qt/optionsmodel -> qt/intro -> qt/guiutil"
    "qt/addressbookpage -> qt/bitcoingui -> qt/walletview -> qt/sendcoinsdialog -> qt/sendcoinsentry -> qt/addressbookpage"
    "anon -> txmempool -> anon"
    "anon -> validation -> anon"
    "consensus/tx_verify -> validation -> consensus/tx_verify"
    "insight/insight -> txdb -> insight/insight"
    "insight/insight -> txmempool -> insight/insight"
    "insight/insight -> validation -> insight/insight"
    "key/extkey -> key_io -> key/extkey"
    "key/extkey -> script/ismine -> key/extkey"
    "key/stealth -> key_io -> key/stealth"
    "pos/kernel -> validation -> pos/kernel"
    "pos/miner -> wallet/hdwallet -> pos/miner"
    "pos/miner -> wallet/hdwallet -> wallet/wallet -> pos/miner"
    "smsg/db -> smsg/smessage -> smsg/db"
    "smsg/smessage -> validation -> smsg/smessage"
    "smsg/smessage -> validationinterface -> smsg/smessage"
    "txdb -> validation -> txdb"
    "usbdevice/debugdevice -> usbdevice/usbdevice -> usbdevice/debugdevice"
    "usbdevice/ledgerdevice -> usbdevice/usbdevice -> usbdevice/ledgerdevice"
    "usbdevice/trezordevice -> usbdevice/usbdevice -> usbdevice/trezordevice"
    "usbdevice/usbdevice -> wallet/hdwallet -> usbdevice/usbdevice"
    "wallet/hdwallet -> wallet/hdwalletdb -> wallet/hdwallet"
    "wallet/hdwallet -> wallet/rpchdwallet -> wallet/hdwallet"
    "wallet/hdwallet -> wallet/wallet -> wallet/hdwallet"
    "anon -> txmempool -> consensus/tx_verify -> anon"
    "init -> usbdevice/rpcusbdevice -> wallet/rpchdwallet -> init"
    "key/extkey -> script/ismine -> keystore -> key/extkey"
    "key/extkey -> key_io -> script/standard -> key/extkey"
    "key/stealth -> key_io -> script/standard -> key/stealth"
    "pos/miner -> wallet/hdwallet -> wallet/rpchdwallet -> pos/miner"
    "wallet/hdwallet -> wallet/rpchdwallet -> wallet/rpcwallet -> wallet/hdwallet"
    "consensus/tx_verify -> smsg/smessage -> wallet/wallet -> txmempool -> consensus/tx_verify"
    "consensus/tx_verify -> smsg/smessage -> wallet/wallet -> wallet/walletdb -> consensus/tx_verify"
    "wallet/feebumper -> wallet/hdwallet -> wallet/rpchdwallet -> wallet/rpcwallet -> wallet/feebumper"
    "init -> usbdevice/rpcusbdevice -> wallet/rpcwallet -> init"
    "init -> usbdevice/rpcusbdevice -> wallet/rpcwallet -> rpc/rawtransaction -> init"
)

EXIT_CODE=0

CIRCULAR_DEPENDENCIES=()

IFS=$'\n'
for CIRC in $(cd src && ../contrib/devtools/circular-dependencies.py {*,*/*,*/*/*}.{h,cpp} | sed -e 's/^Circular dependency: //'); do
    CIRCULAR_DEPENDENCIES+=($CIRC)
    IS_EXPECTED_CIRC=0
    for EXPECTED_CIRC in "${EXPECTED_CIRCULAR_DEPENDENCIES[@]}"; do
        if [[ "${CIRC}" == "${EXPECTED_CIRC}" ]]; then
            IS_EXPECTED_CIRC=1
            break
        fi
    done
    if [[ ${IS_EXPECTED_CIRC} == 0 ]]; then
        echo "A new circular dependency in the form of \"${CIRC}\" appears to have been introduced."
        echo
        EXIT_CODE=1
    fi
done

for EXPECTED_CIRC in "${EXPECTED_CIRCULAR_DEPENDENCIES[@]}"; do
    IS_PRESENT_EXPECTED_CIRC=0
    for CIRC in "${CIRCULAR_DEPENDENCIES[@]}"; do
        if [[ "${CIRC}" == "${EXPECTED_CIRC}" ]]; then
            IS_PRESENT_EXPECTED_CIRC=1
            break
        fi
    done
    if [[ ${IS_PRESENT_EXPECTED_CIRC} == 0 ]]; then
        echo "Good job! The circular dependency \"${EXPECTED_CIRC}\" is no longer present."
        echo "Please remove it from EXPECTED_CIRCULAR_DEPENDENCIES in $0"
        echo "to make sure this circular dependency is not accidentally reintroduced."
        echo
        EXIT_CODE=1
    fi
done

exit ${EXIT_CODE}
