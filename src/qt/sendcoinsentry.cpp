// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/sendcoinsentry.h>
#include <qt/forms/ui_sendcoinsentry.h>

#include <qt/addressbookpage.h>
#include <qt/addresstablemodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>

#include <QApplication>
#include <QClipboard>

SendCoinsEntry::SendCoinsEntry(const PlatformStyle *_platformStyle, QWidget *parent, bool coldstake) :
    QStackedWidget(parent),
    ui(new Ui::SendCoinsEntry),
    model(nullptr),
    platformStyle(_platformStyle),
    m_coldstake(coldstake)
{
    ui->setupUi(this);

    if (m_coldstake) {
        ui->addressBookButton_cs->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
        ui->pasteButton_cs->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
        ui->addressBookButton2_cs->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
        ui->pasteButton2_cs->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
        ui->deleteButton_cs->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));

        setCurrentWidget(ui->SendCoins_cs);

        // normal bitcoin address field
        GUIUtil::setupAddressWidget(ui->stakeAddr, this, true);
        GUIUtil::setupAddressWidget(ui->spendAddr, this);
        // just a label for displaying bitcoin address(es)
        ui->stakeAddr->setFont(GUIUtil::fixedPitchFont());
        ui->spendAddr->setFont(GUIUtil::fixedPitchFont());

        // Connect signals
        connect(ui->payAmount_cs, &BitcoinAmountField::valueChanged, this, &SendCoinsEntry::payAmountChanged);
        connect(ui->checkboxSubtractFeeFromAmount_cs, &QCheckBox::toggled, this, &SendCoinsEntry::subtractFeeFromAmountChanged);
        connect(ui->deleteButton_cs, &QPushButton::clicked, this, &SendCoinsEntry::deleteClicked);
        connect(ui->useAvailableBalanceButton_cs, &QPushButton::clicked, this, &SendCoinsEntry::useAvailableBalanceClicked);

        return;
    }

    ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    ui->pasteButton->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
    ui->deleteButton->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));
    ui->deleteButton_is->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));
    ui->deleteButton_s->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));

    setCurrentWidget(ui->SendCoins);

    if (platformStyle->getUseExtraSpacing())
        ui->payToLayout->setSpacing(4);
    ui->addAsLabel->setPlaceholderText(tr("Enter a label for this address to add it to your address book"));

    // normal bitcoin address field
    GUIUtil::setupAddressWidget(ui->payTo, this);
    // just a label for displaying bitcoin address(es)
    ui->payTo_is->setFont(GUIUtil::fixedPitchFont());

    // Connect signals
    connect(ui->payAmount, &BitcoinAmountField::valueChanged, this, &SendCoinsEntry::payAmountChanged);
    connect(ui->checkboxSubtractFeeFromAmount, &QCheckBox::toggled, this, &SendCoinsEntry::subtractFeeFromAmountChanged);
    connect(ui->deleteButton, &QPushButton::clicked, this, &SendCoinsEntry::deleteClicked);
    connect(ui->deleteButton_is, &QPushButton::clicked, this, &SendCoinsEntry::deleteClicked);
    connect(ui->deleteButton_s, &QPushButton::clicked, this, &SendCoinsEntry::deleteClicked);
    connect(ui->useAvailableBalanceButton, &QPushButton::clicked, this, &SendCoinsEntry::useAvailableBalanceClicked);
}

SendCoinsEntry::~SendCoinsEntry()
{
    delete ui;
}

void SendCoinsEntry::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payTo->setText(QApplication::clipboard()->text());
}

void SendCoinsEntry::on_addressBookButton_clicked()
{
    if(!model)
        return;
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->payTo->setText(dlg.getReturnValue());
        ui->payAmount->setFocus();
    }
}

void SendCoinsEntry::on_payTo_textChanged(const QString &address)
{
    updateLabel(address);
}

void SendCoinsEntry::on_pasteButton_cs_clicked()
{
    // Paste text from clipboard into recipient field
    ui->stakeAddr->setText(QApplication::clipboard()->text());
}

void SendCoinsEntry::on_addressBookButton_cs_clicked()
{
    if(!model)
        return;
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->stakeAddr->setText(dlg.getReturnValue());
        ui->spendAddr->setFocus();
    }
}

void SendCoinsEntry::on_pasteButton2_cs_clicked()
{
    // Paste text from clipboard into recipient field
    ui->spendAddr->setText(QApplication::clipboard()->text());
}

void SendCoinsEntry::on_addressBookButton2_cs_clicked()
{
    if(!model)
        return;
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->spendAddr->setText(dlg.getReturnValue());
        ui->payAmount_cs->setFocus();
    }
}

void SendCoinsEntry::setModel(WalletModel *_model)
{
    this->model = _model;

    if (_model && _model->getOptionsModel())
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsEntry::updateDisplayUnit);

    clear();
}

void SendCoinsEntry::clear()
{
    // clear UI elements for normal payment
    ui->payTo->clear();
    ui->addAsLabel->clear();
    ui->payAmount->clear();
    ui->checkboxSubtractFeeFromAmount->setCheckState(Qt::Unchecked);
    ui->messageTextLabel->clear();
    ui->messageTextLabel->hide();
    ui->messageLabel->hide();
    // clear UI elements for unauthenticated payment request
    ui->payTo_is->clear();
    ui->memoTextLabel_is->clear();
    ui->payAmount_is->clear();
    // clear UI elements for authenticated payment request
    ui->payTo_s->clear();
    ui->memoTextLabel_s->clear();
    ui->payAmount_s->clear();

    ui->stakeAddr->clear();
    ui->spendAddr->clear();
    ui->payAmount_cs->clear();
    ui->checkboxSubtractFeeFromAmount_cs->setCheckState(Qt::Unchecked);
    ui->edtNarration->clear();
    ui->edtNarration_cs->clear();

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void SendCoinsEntry::checkSubtractFeeFromAmount()
{
    ui->checkboxSubtractFeeFromAmount->setChecked(true);
}

void SendCoinsEntry::deleteClicked()
{
    Q_EMIT removeEntry(this);
}

void SendCoinsEntry::useAvailableBalanceClicked()
{
    Q_EMIT useAvailableBalance(this);
}

bool SendCoinsEntry::validate(interfaces::Node& node)
{
    if (!model)
        return false;

    // Check input validity
    bool retval = true;

#ifdef ENABLE_BIP70
    // Skip checks for payment request
    if (recipient.paymentRequest.IsInitialized())
        return retval;
#endif

    if (m_coldstake) {
        if (!model->validateAddress(ui->stakeAddr->text(), true)) {
            ui->stakeAddr->setValid(false);
            retval = false;
        }
        if (!model->validateAddress(ui->spendAddr->text())) {
            ui->spendAddr->setValid(false);
            retval = false;
        }

        if (!ui->payAmount_cs->validate()) {
            retval = false;
        }

        // Sending a zero amount is invalid
        if (ui->payAmount_cs->value(0) <= 0)
        {
            ui->payAmount_cs->setValid(false);
            retval = false;
        }

        // Reject dust outputs:
        if (retval && GUIUtil::isDust(node, ui->spendAddr->text(), ui->payAmount_cs->value())) {
            ui->payAmount_cs->setValid(false);
            retval = false;
        }

        return retval;
    }

    if (!model->validateAddress(ui->payTo->text()))
    {
        ui->payTo->setValid(false);
        retval = false;
    }

    if (!ui->payAmount->validate())
    {
        retval = false;
    }

    // Sending a zero amount is invalid
    if (ui->payAmount->value(nullptr) <= 0)
    {
        ui->payAmount->setValid(false);
        retval = false;
    }

    // Reject dust outputs:
    if (retval && GUIUtil::isDust(node, ui->payTo->text(), ui->payAmount->value())) {
        ui->payAmount->setValid(false);
        retval = false;
    }

    return retval;
}

SendCoinsRecipient SendCoinsEntry::getValue()
{
#ifdef ENABLE_BIP70
    // Payment request
    if (recipient.paymentRequest.IsInitialized())
        return recipient;
#endif

    recipient.m_coldstake = m_coldstake;
    if (m_coldstake) {
        recipient.stake_address = ui->stakeAddr->text();
        recipient.spend_address = ui->spendAddr->text();
        recipient.amount = ui->payAmount_cs->value();
        recipient.narration = ui->edtNarration_cs->text();
        recipient.fSubtractFeeFromAmount = (ui->checkboxSubtractFeeFromAmount_cs->checkState() == Qt::Checked);

        return recipient;
    }

    // Normal payment
    recipient.address = ui->payTo->text();
    recipient.label = ui->addAsLabel->text();
    recipient.amount = ui->payAmount->value();
    recipient.message = ui->messageTextLabel->text();
    recipient.narration = ui->edtNarration->text();
    recipient.fSubtractFeeFromAmount = (ui->checkboxSubtractFeeFromAmount->checkState() == Qt::Checked);

    return recipient;
}

QWidget *SendCoinsEntry::setupTabChain(QWidget *prev)
{
    QWidget::setTabOrder(prev, ui->payTo);
    QWidget::setTabOrder(ui->payTo, ui->addAsLabel);
    QWidget *w = ui->payAmount->setupTabChain(ui->addAsLabel);
    QWidget::setTabOrder(w, ui->checkboxSubtractFeeFromAmount);
    QWidget::setTabOrder(ui->checkboxSubtractFeeFromAmount, ui->addressBookButton);
    QWidget::setTabOrder(ui->addressBookButton, ui->pasteButton);
    QWidget::setTabOrder(ui->pasteButton, ui->deleteButton);
    return ui->deleteButton;
}

void SendCoinsEntry::setValue(const SendCoinsRecipient &value)
{
    recipient = value;

#ifdef ENABLE_BIP70
    if (recipient.paymentRequest.IsInitialized()) // payment request
    {
        if (recipient.authenticatedMerchant.isEmpty()) // unauthenticated
        {
            ui->payTo_is->setText(recipient.address);
            ui->memoTextLabel_is->setText(recipient.message);
            ui->payAmount_is->setValue(recipient.amount);
            ui->payAmount_is->setReadOnly(true);
            setCurrentWidget(ui->SendCoins_UnauthenticatedPaymentRequest);
        }
        else // authenticated
        {
            ui->payTo_s->setText(recipient.authenticatedMerchant);
            ui->memoTextLabel_s->setText(recipient.message);
            ui->payAmount_s->setValue(recipient.amount);
            ui->payAmount_s->setReadOnly(true);
            setCurrentWidget(ui->SendCoins_AuthenticatedPaymentRequest);
        }
    }
    else // normal payment
#endif
    {
        // message
        ui->messageTextLabel->setText(recipient.message);
        ui->messageTextLabel->setVisible(!recipient.message.isEmpty());
        ui->messageLabel->setVisible(!recipient.message.isEmpty());

        ui->addAsLabel->clear();
        ui->payTo->setText(recipient.address); // this may set a label from addressbook
        if (!recipient.label.isEmpty()) // if a label had been set from the addressbook, don't overwrite with an empty label
            ui->addAsLabel->setText(recipient.label);
        ui->payAmount->setValue(recipient.amount);
    }
}

void SendCoinsEntry::setAddress(const QString &address)
{
    ui->payTo->setText(address);
    ui->payAmount->setFocus();
}

void SendCoinsEntry::setAmount(const CAmount &amount)
{
    if (m_coldstake) {
        ui->payAmount_cs->setValue(amount);
        return;
    }
    ui->payAmount->setValue(amount);
}

bool SendCoinsEntry::isClear()
{
    return ui->payTo->text().isEmpty() && ui->payTo_is->text().isEmpty() && ui->payTo_s->text().isEmpty();
}

void SendCoinsEntry::setFocus()
{
    ui->payTo->setFocus();
}

void SendCoinsEntry::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        // Update payAmount with the current unit
        ui->payAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
        ui->payAmount_is->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
        ui->payAmount_s->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
        ui->payAmount_cs->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

bool SendCoinsEntry::updateLabel(const QString &address)
{
    if(!model)
        return false;

    // Fill in label from address book, if address has an associated label
    QString associatedLabel = model->getAddressTableModel()->labelForAddress(address);
    if(!associatedLabel.isEmpty())
    {
        ui->addAsLabel->setText(associatedLabel);
        return true;
    }

    return false;
}
