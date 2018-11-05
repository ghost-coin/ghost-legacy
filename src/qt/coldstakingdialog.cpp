// Copyright (c) 2018 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/coldstakingdialog.h>
#include <qt/forms/ui_coldstakingdialog.h>

#include <qt/guiutil.h>

#include <qt/walletmodel.h>

#include <interfaces/wallet.h>

#include <rpc/rpcutil.h>
#include <util/system.h>
#include <key/extkey.h>

#include <QDebug>

ColdStakingDialog::ColdStakingDialog(QWidget *parent, WalletModel *wm) :
    QDialog(parent), walletModel(wm),
    ui(new Ui::ColdStakingDialog)
{
    ui->setupUi(this);

    ui->lblWallet->setText(QString::fromStdString(walletModel->wallet().getWalletName()));

    GUIUtil::setupAddressWidget(ui->coldStakeChangeAddr, this, true);

    QString change_spend;
    getChangeSettings(change_spend, m_coldStakeChangeAddress);
    ui->coldStakeChangeAddr->setText(m_coldStakeChangeAddress);

    UniValue rv;
    QString sCommand = "getcoldstakinginfo";
    if (walletModel->tryCallRpc(sCommand, rv)) {
        if (rv["enabled"].isBool()) {
            ui->lblEnabled->setText(rv["enabled"].get_bool() ? "True" : "False");
        }
        if (rv["percent_in_coldstakeable_script"].isNum()) {
            ui->lblPercent->setText(QString::fromStdString(strprintf("%.02f", rv["percent_in_coldstakeable_script"].get_real())));
        }
    }

    return;
};

bool ColdStakingDialog::getChangeSettings(QString &change_spend, QString &change_stake)
{
    UniValue rv;
    QString sCommand = "walletsettings changeaddress";
    if (walletModel->tryCallRpc(sCommand, rv)) {
        if (rv["changeaddress"].isObject()
            && rv["changeaddress"]["address_standard"].isStr()) {
            change_spend = QString::fromStdString(rv["changeaddress"]["address_standard"].get_str());
        }
        if (rv["changeaddress"].isObject()
            && rv["changeaddress"]["coldstakingaddress"].isStr()) {
            change_stake = QString::fromStdString(rv["changeaddress"]["coldstakingaddress"].get_str());
        }
        return true;
    }
    return false;
};

void ColdStakingDialog::on_btnApply_clicked()
{
    QString newColdStakeChangeAddress = ui->coldStakeChangeAddr->text();
    QString sCommand;

    if (newColdStakeChangeAddress != m_coldStakeChangeAddress) {
        QString change_spend, change_stake;
        getChangeSettings(change_spend, m_coldStakeChangeAddress);

        sCommand = "walletsettings changeaddress {";
        if (!change_spend.isEmpty()) {
            sCommand += "\"address_standard\":\""+change_spend+"\"";
        }
        if (!newColdStakeChangeAddress.isEmpty()) {
            if (!change_spend.isEmpty()) {
                sCommand += ",";
            }
            sCommand += "\"coldstakingaddress\":\""+newColdStakeChangeAddress+"\"";
        }
        sCommand += "}";
    }

    if (!sCommand.isEmpty()) {
        UniValue rv;
        if (!walletModel->tryCallRpc(sCommand, rv)) {
            return;
        }
    }

    close();
    return;
};

void ColdStakingDialog::on_btnCancel_clicked()
{
    close();
    return;
};
