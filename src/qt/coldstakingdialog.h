// Copyright (c) 2018 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_QT_COLDSTAKINGDIALOG_H
#define PARTICL_QT_COLDSTAKINGDIALOG_H

#include <QDialog>

class WalletModel;

namespace Ui {
    class ColdStakingDialog;
}

class ColdStakingDialog : public QDialog
{
    Q_OBJECT
private:
    WalletModel *walletModel;

    QString m_coldStakeChangeAddress;

    bool getChangeSettings(QString &change_spend, QString &change_stake);

public:
    explicit ColdStakingDialog(QWidget *parent, WalletModel *wm);

private Q_SLOTS:
    void on_btnCancel_clicked();
    void on_btnApply_clicked();

private:
    Ui::ColdStakingDialog *ui;
};

#endif // PARTICL_QT_COLDSTAKINGDIALOG_H
