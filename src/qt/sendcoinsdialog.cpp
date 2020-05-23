// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/sendcoinsdialog.h>
#include <qt/forms/ui_sendcoinsdialog.h>

#include <qt/addresstablemodel.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/coincontroldialog.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/sendcoinsentry.h>

#include <chainparams.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <policy/fees.h>
#include <txmempool.h>
#include <ui_interface.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/wallet.h>

#include <QFontMetrics>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
#include <QApplication>


#include <anon.h>
#include <wallet/hdwallet.h>
#include <univalue.h>
#include <util/fees.h>


static const std::array<int, 9> confTargets = { {2, 4, 6, 12, 24, 48, 144, 504, 1008} };
int getConfTargetForIndex(int index) {
    if (index+1 > static_cast<int>(confTargets.size())) {
        return confTargets.back();
    }
    if (index < 0) {
        return confTargets[0];
    }
    return confTargets[index];
}
int getIndexForConfTarget(int target) {
    for (unsigned int i = 0; i < confTargets.size(); i++) {
        if (confTargets[i] >= target) {
            return i;
        }
    }
    return confTargets.size() - 1;
}

SendCoinsDialog::SendCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SendCoinsDialog),
    clientModel(nullptr),
    model(nullptr),
    fNewRecipientAllowed(true),
    fFeeMinimized(true),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->addButton->setIcon(QIcon());
        ui->clearButton->setIcon(QIcon());
        ui->sendButton->setIcon(QIcon());
    } else {
        ui->addButton->setIcon(_platformStyle->SingleColorIcon(":/icons/add"));
        ui->addButtonCS->setIcon(_platformStyle->SingleColorIcon(":/icons/add"));
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->sendButton->setIcon(_platformStyle->SingleColorIcon(":/icons/send"));
    }

    GUIUtil::setupAddressWidget(ui->lineEditCoinControlChange, this);

    addEntry();

    connect(ui->addButton, &QPushButton::clicked, this, &SendCoinsDialog::addEntry);
    connect(ui->addButtonCS, &QPushButton::clicked, this, &SendCoinsDialog::addEntryCS);
    connect(ui->clearButton, &QPushButton::clicked, this, &SendCoinsDialog::clear);

    // Coin Control
    connect(ui->pushButtonCoinControl, &QPushButton::clicked, this, &SendCoinsDialog::coinControlButtonClicked);
    connect(ui->checkBoxCoinControlChange, &QCheckBox::stateChanged, this, &SendCoinsDialog::coinControlChangeChecked);
    connect(ui->lineEditCoinControlChange, &QValidatedLineEdit::textEdited, this, &SendCoinsDialog::coinControlChangeEdited);

    // Coin Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardLowOutputAction = new QAction(tr("Copy dust"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardQuantity);
    connect(clipboardAmountAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAmount);
    connect(clipboardFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardFee);
    connect(clipboardAfterFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAfterFee);
    connect(clipboardBytesAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardBytes);
    connect(clipboardLowOutputAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardLowOutput);
    connect(clipboardChangeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardChange);

    connect(ui->cbxTypeFrom, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &SendCoinsDialog::cbxTypeFromChanged);

    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlAfterFee->addAction(clipboardAfterFeeAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlLowOutput->addAction(clipboardLowOutputAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);

    // init transaction fee section
    QSettings settings;
    if (!settings.contains("fFeeSectionMinimized"))
        settings.setValue("fFeeSectionMinimized", true);
    if (!settings.contains("nFeeRadio") && settings.contains("nTransactionFee") && settings.value("nTransactionFee").toLongLong() > 0) // compatibility
        settings.setValue("nFeeRadio", 1); // custom
    if (!settings.contains("nFeeRadio"))
        settings.setValue("nFeeRadio", 0); // recommended
    if (!settings.contains("nSmartFeeSliderPosition"))
        settings.setValue("nSmartFeeSliderPosition", 0);
    if (!settings.contains("nTransactionFee"))
        settings.setValue("nTransactionFee", (qint64)DEFAULT_PAY_TX_FEE);
    ui->groupFee->setId(ui->radioSmartFee, 0);
    ui->groupFee->setId(ui->radioCustomFee, 1);
    ui->groupFee->button((int)std::max(0, std::min(1, settings.value("nFeeRadio").toInt())))->setChecked(true);
    ui->customFee->SetAllowEmpty(false);
    ui->customFee->setValue(settings.value("nTransactionFee").toLongLong());
    minimizeFeeSection(settings.value("fFeeSectionMinimized").toBool());


    if (!settings.contains("nRingSize")) {
        settings.setValue("nRingSize", (int)DEFAULT_RING_SIZE);
    }
    if (!settings.contains("nInputsPerMLSAG")) {
        settings.setValue("nInputsPerMLSAG", (int)DEFAULT_INPUTS_PER_SIG);
    }
    ui->spinRingSize->setValue(settings.value("nRingSize").toInt());
    ui->spinMaxInputs->setValue(settings.value("nInputsPerMLSAG").toInt());
}

void SendCoinsDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (_clientModel) {
        connect(_clientModel, &ClientModel::numBlocksChanged, this, &SendCoinsDialog::updateSmartFeeLabel);
    }
}

void SendCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        for(int i = 0; i < ui->entries->count(); ++i)
        {
            SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if(entry)
            {
                entry->setModel(_model);
            }
        }

        interfaces::WalletBalances balances = _model->wallet().getBalances();
        setBalance(balances);
        connect(_model, &WalletModel::balanceChanged, this, &SendCoinsDialog::setBalance);
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::updateDisplayUnit);
        updateDisplayUnit();

        // Coin Control
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(_model->getOptionsModel(), &OptionsModel::coinControlFeaturesChanged, this, &SendCoinsDialog::coinControlFeatureChanged);
        ui->frameCoinControl->setVisible(_model->getOptionsModel()->getCoinControlFeatures());
        coinControlUpdateLabels();

        // fee section
        for (const int n : confTargets) {
            ui->confTargetSelector->addItem(tr("%1 (%2 blocks)").arg(GUIUtil::formatNiceTimeOffset(n*Params().GetConsensus().nPowTargetSpacing)).arg(n));
        }
        connect(ui->confTargetSelector, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &SendCoinsDialog::updateSmartFeeLabel);
        connect(ui->confTargetSelector, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(ui->groupFee, static_cast<void (QButtonGroup::*)(int)>(&QButtonGroup::buttonClicked), this, &SendCoinsDialog::updateFeeSectionControls);
        connect(ui->groupFee, static_cast<void (QButtonGroup::*)(int)>(&QButtonGroup::buttonClicked), this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(ui->customFee, &BitcoinAmountField::valueChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(ui->optInRBF, &QCheckBox::stateChanged, this, &SendCoinsDialog::updateSmartFeeLabel);
        connect(ui->optInRBF, &QCheckBox::stateChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        CAmount requiredFee = model->wallet().getRequiredFee(1000);
        ui->customFee->SetMinValue(requiredFee);
        if (ui->customFee->value() < requiredFee) {
            ui->customFee->setValue(requiredFee);
        }
        ui->customFee->setSingleStep(requiredFee);
        updateFeeSectionControls();
        updateSmartFeeLabel();

        // set default rbf checkbox state
        ui->optInRBF->setCheckState(Qt::Checked);

        if (model->wallet().privateKeysDisabled()) {
            ui->sendButton->setText(tr("Cr&eate Unsigned"));
            ui->sendButton->setToolTip(tr("Creates a Partially Signed Bitcoin Transaction (PSBT) for use with e.g. an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(PACKAGE_NAME));
        }

        // set the smartfee-sliders default value (wallets default conf.target or last stored value)
        QSettings settings;
        if (settings.value("nSmartFeeSliderPosition").toInt() != 0) {
            // migrate nSmartFeeSliderPosition to nConfTarget
            // nConfTarget is available since 0.15 (replaced nSmartFeeSliderPosition)
            int nConfirmTarget = 25 - settings.value("nSmartFeeSliderPosition").toInt(); // 25 == old slider range
            settings.setValue("nConfTarget", nConfirmTarget);
            settings.remove("nSmartFeeSliderPosition");
        }
        if (settings.value("nConfTarget").toInt() == 0)
            ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(model->wallet().getConfirmTarget()));
        else
            ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(settings.value("nConfTarget").toInt()));
    }
}

SendCoinsDialog::~SendCoinsDialog()
{
    QSettings settings;
    settings.setValue("fFeeSectionMinimized", fFeeMinimized);
    settings.setValue("nFeeRadio", ui->groupFee->checkedId());
    settings.setValue("nConfTarget", getConfTargetForIndex(ui->confTargetSelector->currentIndex()));
    settings.setValue("nTransactionFee", (qint64)ui->customFee->value());

    settings.setValue("nRingSize", ui->spinRingSize->value());
    settings.setValue("nInputsPerMLSAG", ui->spinMaxInputs->value());

    delete ui;
}

bool SendCoinsDialog::PrepareSendText(QString& question_string, QString& informative_text, QString& detailed_text, QString& sCommand, QString& sCoinControl)
{
    QList<SendCoinsRecipient> recipients;
    bool valid = true;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            if(entry->validate(model->node()))
            {
                recipients.append(entry->getValue());
            }
            else if (valid)
            {
                ui->scrollArea->ensureWidgetVisible(entry);
                valid = false;
            }
        }
    }

    if(!valid || recipients.isEmpty())
    {
        return false;
    }

    fNewRecipientAllowed = false;
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        fNewRecipientAllowed = true;
        return false;
    }

    // prepare transaction for getting txFee earlier
    m_current_transaction = MakeUnique<WalletModelTransaction>(recipients);
    WalletModel::SendCoinsReturn prepareStatus;

    // Always use a CCoinControl instance, use the CoinControlDialog instance if CoinControl has been enabled
    CCoinControl ctrl;
    if (model->getOptionsModel()->getCoinControlFeatures())
        ctrl = *CoinControlDialog::coinControl();

    updateCoinControlState(ctrl);

    prepareStatus = model->prepareTransaction(*m_current_transaction, ctrl);
    if (prepareStatus.status != WalletModel::OK)
    {
        // process prepareStatus and on error generate message shown to user
        processSendCoinsReturn(prepareStatus.status, BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), m_current_transaction->getTransactionFee()));

        fNewRecipientAllowed = true;
        return false;
    };

    sCommand = "sendtypeto ";

    // TODO: Translations?
    QString sTypeFrom = ui->cbxTypeFrom->currentText();
    QString sTypeTo = ui->cbxTypeTo->currentText();

    sCommand += sTypeFrom.toLower() + " ";
    sCommand += sTypeTo.toLower();

    sCommand += " [";

    int nRecipient = 0;
    for (const auto &rcp : m_current_transaction->getRecipients()) {
        if (nRecipient > 0)
            sCommand += ",";

        if (rcp.m_coldstake) {
            QString build_script = "buildscript {\"recipe\":\"ifcoinstake\",\"addrstake\":\""
                + rcp.stake_address + "\",\"addrspend\":\"" + rcp.spend_address + "\"}";
            UniValue rv;
            if (!model->tryCallRpc(build_script, rv)) {
                return false;
            }

            sCommand += "{\"address\":\"script\"";
            sCommand += ",\"script\":\"" + QString::fromStdString(rv["hex"].get_str()) + "\"";
        } else {
            sCommand += "{\"address\":\"" + rcp.address + "\"";
        }
        sCommand += ",\"amount\":"
            + BitcoinUnits::format(BitcoinUnits::BTC, rcp.amount, false, BitcoinUnits::separatorNever);

        if (rcp.fSubtractFeeFromAmount)
            sCommand += ",\"subfee\":true";

        if (!rcp.narration.isEmpty())
            sCommand += ",\"narr\":\""+rcp.narration+"\"";
        sCommand += "}";

        nRecipient++;
    }

    int nRingSize = ui->spinRingSize->value();
    int nMaxInputs = ui->spinMaxInputs->value();

    sCommand += "] \"\" \"\" "+QString::number(nRingSize)+" "+QString::number(nMaxInputs);

    sCoinControl = " {";
    sCoinControl += "\"replaceable\":" + QString::fromUtf8((ui->optInRBF->isChecked() ? "true" : "false"));

    if (ctrl.m_feerate) {
        sCoinControl += ",\"feeRate\":" + QString::fromStdString(ctrl.m_feerate->ToString(false));
    } else {
        std::string sFeeMode;
        if (StringFromFeeMode(ctrl.m_fee_mode, sFeeMode))
            sCoinControl += ",\"estimate_mode\":\"" + QString::fromStdString(sFeeMode) +"\"";
        if (ctrl.m_confirm_target)
            sCoinControl += ",\"conf_target\":" + QString::number(*ctrl.m_confirm_target);
    }

    if (!boost::get<CNoDestination>(&ctrl.destChange)) {
        sCoinControl += ",\"changeaddress\":\""+QString::fromStdString(EncodeDestination(ctrl.destChange))+"\"";
    }

    if (ctrl.NumSelected() > 0)  {
        sCoinControl += ",\"inputs\":[";
        bool fNeedCommaInputs = false;
        for (const auto &op : ctrl.setSelected) {
            sCoinControl += fNeedCommaInputs ? ",{" : "{";
            sCoinControl += "\"tx\":\"" + QString::fromStdString(op.hash.ToString()) + "\"";
            sCoinControl += ",\"n\":" + QString::number(op.n);
            sCoinControl += "}";
            fNeedCommaInputs = true;
        }
        sCoinControl += "]";
    }
    sCoinControl += "} ";

    UniValue rv;
    QString sGetFeeCommand = sCommand + " true" + sCoinControl;
    if (!model->tryCallRpc(sGetFeeCommand, rv)) {
        return false;
    }

    double rFee = rv["fee"].get_real();

    bool fSubbedFee = rv["outputs_fee"].size() > 0 ? true : false;

    size_t nBytes = rv["bytes"].get_int64();
    bool fNeedHWDevice = rv["need_hwdevice"].get_bool();

    CAmount txFee = rFee * COIN;

    // Format confirmation message
    QStringList formatted;
    for (const auto &rcp : m_current_transaction->getRecipients())
    {
        CAmount nValue = rcp.amount;
        const UniValue &uv = rv["outputs_fee"][rcp.address.toStdString().c_str()];
        if (uv.isNum()) {
            nValue = uv.get_int64();
        }
        // generate amount string with wallet name in case of multiwallet
        QString amount = BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), nValue);
        if (model->isMultiwallet()) {
            amount.append(tr(" from wallet '%1'").arg(GUIUtil::HtmlEscape(model->getWalletName())));
        }
        // generate monospace address string
        QString address;
        if (rcp.m_coldstake) {
            address = "<span style='font-family: monospace;'>Spend: " + rcp.spend_address;
            address.append("<br/>Stake: " + rcp.stake_address);
            address.append("</span>");
        } else {
            address = "<span style='font-family: monospace;'>" + rcp.address;
            address.append("</span>");
        }

        QString recipientElement;

        {
            if(rcp.label.length() > 0) // label with address
            {
                recipientElement.append(tr("%1 to '%2'").arg(amount, GUIUtil::HtmlEscape(rcp.label)));
                recipientElement.append(QString(" (%1)").arg(address));
            }
            else // just address
            {
                recipientElement.append(tr("%1 to %2").arg(amount, address));
            }
        }
        formatted.append(recipientElement);
    }

    if (model->wallet().privateKeysDisabled()) {
        question_string.append(tr("Do you want to draft this transaction?"));
    } else {
        question_string.append(tr("Are you sure you want to send?"));
    }

    question_string.append("<br /><span style='font-size:10pt;'>");
    if (model->wallet().privateKeysDisabled()) {
        //question_string.append(tr("Please, review your transaction proposal. This will produce a Partially Signed Bitcoin Transaction (PSBT) which you can save or copy and then sign with e.g. an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(PACKAGE_NAME));
        // TODO
        question_string.append(tr("Private keys disabled."));
    } else {
        question_string.append(tr("Please, review your transaction."));
    }
    question_string.append("</span>%1");

    if(txFee > 0)
    {
        // append fee string if a fee is required
        question_string.append("<hr /><b>");
        question_string.append(tr("Estimated Transaction fee"));
        question_string.append("</b>");

        // append transaction size
        //question_string.append(" (" + QString::number((double)m_current_transaction->getTransactionSize() / 1000) + " kB): ");
        question_string.append(" (" + QString::number((double)nBytes / 1000) + " kB): ");

        // append transaction fee value
        question_string.append("<span style='color:#aa0000; font-weight:bold;'>");
        question_string.append(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), txFee));
        question_string.append("</span><br />");

        if (fSubbedFee)
            question_string.append(tr("removed for transaction fee"));
        else
            question_string.append(tr("added as transaction fee"));

        // append RBF message according to transaction's signalling
        question_string.append("<span style='font-size:10pt; font-weight:normal;'>");
        if (ui->optInRBF->isChecked()) {
            question_string.append(tr("You can increase the fee later (signals Replace-By-Fee, BIP-125)."));
        } else {
            question_string.append(tr("Not signalling Replace-By-Fee, BIP-125."));
        }
        question_string.append("</span>");
    }

    // add total amount in all subdivision units
    question_string.append("<hr />");

    CAmount totalAmount = m_current_transaction->getTotalTransactionAmount();
    if (!fSubbedFee)
        totalAmount += txFee;

    QStringList alternativeUnits;
    for (const BitcoinUnits::Unit u : BitcoinUnits::availableUnits())
    {
        if(u != model->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
    }
    question_string.append(QString("<b>%1</b>: <b>%2</b>").arg(tr("Total Amount"))
        .arg(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), totalAmount)));
    question_string.append(QString("<br /><span style='font-size:10pt; font-weight:normal;'>(=%1)</span>")
        .arg(alternativeUnits.join(" " + tr("or") + " ")));

    if (formatted.size() > 1) {
        question_string = question_string.arg("");
        informative_text = tr("To review recipient list click \"Show Details...\"");
        detailed_text = formatted.join("\n\n");
    } else {
        question_string = question_string.arg("<br /><br />" + formatted.at(0));
    }

    if (fNeedHWDevice) {
        question_string.append("<hr /><span><b>");
        question_string.append(tr("Your hardware device must be connected to sign this txn."));
        question_string.append("</b></span>");
    }

    return true;
}

void SendCoinsDialog::on_sendButton_clicked()
{
    if(!model || !model->getOptionsModel())
        return;


    QString question_string, informative_text, detailed_text, sCommand, sCoinControl;
    if (!PrepareSendText(question_string, informative_text, detailed_text, sCommand, sCoinControl)) return;
    assert(m_current_transaction);

    const QString confirmation = model->wallet().privateKeysDisabled() ? tr("Confirm transaction proposal") : tr("Confirm send coins");
    const QString confirmButtonText = model->wallet().privateKeysDisabled() ? tr("Create Unsigned") : tr("Send");
    SendConfirmationDialog confirmationDialog(confirmation, question_string, informative_text, detailed_text, SEND_CONFIRM_DELAY, confirmButtonText, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = static_cast<QMessageBox::StandardButton>(confirmationDialog.result());

    if(retval != QMessageBox::Yes)
    {
        fNewRecipientAllowed = true;
        return;
    }

    WalletModel::SendCoinsReturn sendStatus = WalletModel::OK;

    sCommand += " false";
    sCommand += sCoinControl;

    UniValue rv;
    uint256 hashSent;
    if (!model->tryCallRpc(sCommand, rv)) {
        sendStatus = WalletModel::TransactionCreationFailed;

        //bool send_failure = false;
        //if (model->wallet().privateKeysDisabled()) {

            //CMutableTransaction mtx = CMutableTransaction{*(currentTransaction.getWtx())};
            //PartiallySignedTransaction psbtx(mtx);
            //bool complete = false;
            //const TransactionError err = model->wallet().fillPSBT(SIGHASH_ALL, false /* sign */, true /* bip32derivs */, psbtx, complete);
            //assert(!complete);
            //assert(err == TransactionError::OK);
            //// Serialize the PSBT
            //CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
            //ssTx << psbtx;
            //GUIUtil::setClipboard(EncodeBase64(ssTx.str()).c_str());
            //Q_EMIT message(tr("PSBT copied"), "Copied to clipboard", CClientUIInterface::MSG_INFORMATION);

        //} else {
        hashSent.SetHex(rv.get_str());
    }

    // Update Addressbook
    for (const auto &rcp : m_current_transaction->getRecipients()) {
        if (rcp.m_coldstake) {
            continue;
        }
        sCommand = "manageaddressbook newsend ";
        sCommand += rcp.address;
        QString strLabel = rcp.label;
        sCommand += strLabel.isEmpty() ? " \"\"" : (" \"" + strLabel + "\"");
        sCommand += " send";

        model->tryCallRpc(sCommand, rv);
    }

    processSendCoinsReturn(sendStatus);

    if (sendStatus.status == WalletModel::OK) {
        accept();
        CoinControlDialog::coinControl()->UnSelectAll();
        coinControlUpdateLabels();
        //Q_EMIT coinsSent(currentTransaction.getWtx()->GetHash());
        Q_EMIT coinsSent(hashSent);

    //bool send_failure = false;
    //if (model->privateKeysDisabled()) {
        //CMutableTransaction mtx = CMutableTransaction{*(currentTransaction.getWtx())};
        //PartiallySignedTransaction psbtx(mtx);
        //bool complete = false;
        //const TransactionError err = model->wallet().fillPSBT(psbtx, complete, SIGHASH_ALL, false /* sign */, true /* bip32derivs */);
        //assert(!complete);
        //assert(err == TransactionError::OK);
        //// Serialize the PSBT
        //CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        //ssTx << psbtx;
        //GUIUtil::setClipboard(EncodeBase64(ssTx.str()).c_str());
        //Q_EMIT message(tr("PSBT copied"), "Copied to clipboard", CClientUIInterface::MSG_INFORMATION);
    //}
    }
    fNewRecipientAllowed = true;
    m_current_transaction.reset();
}

void SendCoinsDialog::clear()
{
    m_current_transaction.reset();

    // Clear coin control settings
    CoinControlDialog::coinControl()->UnSelectAll();
    ui->checkBoxCoinControlChange->setChecked(false);
    ui->lineEditCoinControlChange->clear();
    coinControlUpdateLabels();

    // Remove entries until only one left
    while(ui->entries->count())
    {
        ui->entries->takeAt(0)->widget()->deleteLater();
    }

    ui->cbxTypeFrom->setCurrentIndex(ui->cbxTypeFrom->findText("Part"));
    ui->cbxTypeTo->setCurrentIndex(ui->cbxTypeTo->findText("Part"));

    addEntry();

    updateTabsAndLabels();
}

void SendCoinsDialog::reject()
{
    clear();
}

void SendCoinsDialog::accept()
{
    clear();
}

SendCoinsEntry *SendCoinsDialog::addEntry()
{
    SendCoinsEntry *entry = new SendCoinsEntry(platformStyle, this);
    entry->setModel(model);
    ui->entries->addWidget(entry);
    connect(entry, &SendCoinsEntry::removeEntry, this, &SendCoinsDialog::removeEntry);
    connect(entry, &SendCoinsEntry::useAvailableBalance, this, &SendCoinsDialog::useAvailableBalance);
    connect(entry, &SendCoinsEntry::payAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
    connect(entry, &SendCoinsEntry::subtractFeeFromAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());

    updateTabsAndLabels();
    return entry;
}

SendCoinsEntry *SendCoinsDialog::addEntryCS()
{
    if (ui->entries->count() == 1) {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if (entry->isClear() && !entry->m_coldstake) {
            ui->entries->takeAt(0)->widget()->deleteLater();
        }
    }

    SendCoinsEntry *entry = new SendCoinsEntry(platformStyle, this, true);
    entry->setModel(model);
    ui->entries->addWidget(entry);
    connect(entry, &SendCoinsEntry::removeEntry, this, &SendCoinsDialog::removeEntry);
    connect(entry, &SendCoinsEntry::useAvailableBalance, this, &SendCoinsDialog::useAvailableBalance);
    connect(entry, &SendCoinsEntry::payAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
    connect(entry, &SendCoinsEntry::subtractFeeFromAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());

    updateTabsAndLabels();
    return entry;
}

void SendCoinsDialog::updateTabsAndLabels()
{
    setupTabChain(nullptr);
    coinControlUpdateLabels();
}

void SendCoinsDialog::removeEntry(SendCoinsEntry* entry)
{
    entry->hide();

    // If the last entry is about to be removed add an empty one
    if (ui->entries->count() == 1)
        addEntry();

    entry->deleteLater();

    updateTabsAndLabels();
}

QWidget *SendCoinsDialog::setupTabChain(QWidget *prev)
{
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            prev = entry->setupTabChain(prev);
        }
    }
    QWidget::setTabOrder(prev, ui->sendButton);
    QWidget::setTabOrder(ui->sendButton, ui->clearButton);
    QWidget::setTabOrder(ui->clearButton, ui->addButton);
    return ui->addButton;
}

void SendCoinsDialog::setAddress(const QString &address)
{
    SendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setAddress(address);
}

void SendCoinsDialog::pasteEntry(const SendCoinsRecipient &rv)
{
    if(!fNewRecipientAllowed)
        return;

    SendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setValue(rv);
    updateTabsAndLabels();
}

bool SendCoinsDialog::handlePaymentRequest(const SendCoinsRecipient &rv)
{
    // Just paste the entry, all pre-checks
    // are done in paymentserver.cpp.
    pasteEntry(rv);
    return true;
}

void SendCoinsDialog::setBalance(const interfaces::WalletBalances& balances)
{
    if(model && model->getOptionsModel())
    {
        CAmount balance = balances.balance;
        if (model->wallet().privateKeysDisabled()) {
            balance = balances.watch_only_balance;
            ui->labelBalanceName->setText(tr("Watch-only balance:"));
        }
        QString sBalance = BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), balance);

        if (balances.balanceBlind > 0)
            sBalance += "\n" + BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), balances.balanceBlind) + " B";
        if (balances.balanceAnon > 0)
            sBalance += "\n" + BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), balances.balanceAnon) + " A";
        ui->labelBalance->setText(sBalance);
    }
}

void SendCoinsDialog::updateDisplayUnit()
{
    setBalance(model->wallet().getBalances());
    ui->customFee->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    updateSmartFeeLabel();
}

void SendCoinsDialog::processSendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    // Default to a warning message, override if error message is needed
    msgParams.second = CClientUIInterface::MSG_WARNING;

    // This comment is specific to SendCoinsDialog usage of WalletModel::SendCoinsReturn.
    // All status values are used only in WalletModel::prepareTransaction()
    switch(sendCoinsReturn.status)
    {
    case WalletModel::InvalidAddress:
        msgParams.first = tr("The recipient address is not valid. Please recheck.");
        break;
    case WalletModel::InvalidAmount:
        msgParams.first = tr("The amount to pay must be larger than 0.");
        break;
    case WalletModel::AmountExceedsBalance:
        msgParams.first = tr("The amount exceeds your balance.");
        break;
    case WalletModel::AmountWithFeeExceedsBalance:
        msgParams.first = tr("The total exceeds your balance when the %1 transaction fee is included.").arg(msgArg);
        break;
    case WalletModel::DuplicateAddress:
        msgParams.first = tr("Duplicate address found: addresses should only be used once each.");
        break;
    case WalletModel::TransactionCreationFailed:
        msgParams.first = tr("Transaction creation failed!");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::AbsurdFee:
        msgParams.first = tr("A fee higher than %1 is considered an absurdly high fee.").arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), model->wallet().getDefaultMaxTxFee()));
        break;
    case WalletModel::PaymentRequestExpired:
        msgParams.first = tr("Payment request expired.");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    // included to prevent a compiler warning.
    case WalletModel::OK:
    default:
        return;
    }

    Q_EMIT message(tr("Send Coins"), msgParams.first, msgParams.second);
}

void SendCoinsDialog::minimizeFeeSection(bool fMinimize)
{
    ui->labelFeeMinimized->setVisible(fMinimize);
    ui->buttonChooseFee  ->setVisible(fMinimize);
    ui->buttonMinimizeFee->setVisible(!fMinimize);
    ui->frameFeeSelection->setVisible(!fMinimize);
    ui->horizontalLayoutSmartFee->setContentsMargins(0, (fMinimize ? 0 : 6), 0, 0);
    fFeeMinimized = fMinimize;
}

void SendCoinsDialog::on_buttonChooseFee_clicked()
{
    minimizeFeeSection(false);
}

void SendCoinsDialog::on_buttonMinimizeFee_clicked()
{
    updateFeeMinimizedLabel();
    minimizeFeeSection(true);
}

void SendCoinsDialog::useAvailableBalance(SendCoinsEntry* entry)
{
    // Get CCoinControl instance if CoinControl is enabled or create a new one.
    CCoinControl coin_control;
    if (model->getOptionsModel()->getCoinControlFeatures()) {
        coin_control = *CoinControlDialog::coinControl();
    }

    QString sTypeFrom = ui->cbxTypeFrom->currentText().toLower();
    // Include watch-only for wallets without private key
    coin_control.fAllowWatchOnly = model->wallet().privateKeysDisabled();

    // Calculate available amount to send.

    CAmount amount =
        sTypeFrom == "anon" ? model->wallet().getAvailableAnonBalance(coin_control) :
        sTypeFrom == "blind" ? model->wallet().getAvailableBlindBalance(coin_control) :
        model->wallet().getAvailableBalance(coin_control);

    for (int i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry* e = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if (e && !e->isHidden() && e != entry) {
            amount -= e->getValue().amount;
        }
    }

    if (amount > 0) {
      entry->checkSubtractFeeFromAmount();
      entry->setAmount(amount);
    } else {
      entry->setAmount(0);
    }
}

void SendCoinsDialog::updateFeeSectionControls()
{
    ui->confTargetSelector      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee           ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee2          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee3          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelFeeEstimation      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelCustomFeeWarning   ->setEnabled(ui->radioCustomFee->isChecked());
    ui->labelCustomPerKilobyte  ->setEnabled(ui->radioCustomFee->isChecked());
    ui->customFee               ->setEnabled(ui->radioCustomFee->isChecked());
}

void SendCoinsDialog::updateFeeMinimizedLabel()
{
    if(!model || !model->getOptionsModel())
        return;

    if (ui->radioSmartFee->isChecked())
        ui->labelFeeMinimized->setText(ui->labelSmartFee->text());
    else {
        ui->labelFeeMinimized->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), ui->customFee->value()) + "/kB");
    }
}

void SendCoinsDialog::updateCoinControlState(CCoinControl& ctrl)
{
    if (ui->radioCustomFee->isChecked()) {
        ctrl.m_feerate = CFeeRate(ui->customFee->value());
    } else {
        ctrl.m_feerate.reset();
    }
    // Avoid using global defaults when sending money from the GUI
    // Either custom fee will be used or if not selected, the confirmation target from dropdown box
    ctrl.m_confirm_target = getConfTargetForIndex(ui->confTargetSelector->currentIndex());
    ctrl.m_signal_bip125_rbf = ui->optInRBF->isChecked();
    // Include watch-only for wallets without private key
    ctrl.fAllowWatchOnly = model->wallet().privateKeysDisabled();
}

void SendCoinsDialog::updateSmartFeeLabel()
{
    if(!model || !model->getOptionsModel())
        return;
    CCoinControl coin_control;
    updateCoinControlState(coin_control);
    coin_control.m_feerate.reset(); // Explicitly use only fee estimation rate for smart fee labels
    int returned_target;
    FeeReason reason;
    CFeeRate feeRate = CFeeRate(model->wallet().getMinimumFee(1000, coin_control, &returned_target, &reason));

    ui->labelSmartFee->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), feeRate.GetFeePerK()) + "/kB");

    if (reason == FeeReason::FALLBACK) {
        ui->labelSmartFee2->show(); // (Smart fee not initialized yet. This usually takes a few blocks...)
        ui->labelFeeEstimation->setText("");
        ui->fallbackFeeWarningLabel->setVisible(true);
        int lightness = ui->fallbackFeeWarningLabel->palette().color(QPalette::WindowText).lightness();
        QColor warning_colour(255 - (lightness / 5), 176 - (lightness / 3), 48 - (lightness / 14));
        ui->fallbackFeeWarningLabel->setStyleSheet("QLabel { color: " + warning_colour.name() + "; }");
        ui->fallbackFeeWarningLabel->setIndent(GUIUtil::TextWidth(QFontMetrics(ui->fallbackFeeWarningLabel->font()), "x"));
    }
    else
    {
        ui->labelSmartFee2->hide();
        ui->labelFeeEstimation->setText(tr("Estimated to begin confirmation within %n block(s).", "", returned_target));
        ui->fallbackFeeWarningLabel->setVisible(false);
    }

    updateFeeMinimizedLabel();
}

// Coin Control: copy label "Quantity" to clipboard
void SendCoinsDialog::coinControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void SendCoinsDialog::coinControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void SendCoinsDialog::coinControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "After fee" to clipboard
void SendCoinsDialog::coinControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Bytes" to clipboard
void SendCoinsDialog::coinControlClipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Dust" to clipboard
void SendCoinsDialog::coinControlClipboardLowOutput()
{
    GUIUtil::setClipboard(ui->labelCoinControlLowOutput->text());
}

// Coin Control: copy label "Change" to clipboard
void SendCoinsDialog::coinControlClipboardChange()
{
    GUIUtil::setClipboard(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

void SendCoinsDialog::cbxTypeFromChanged(int index)
{
    if (model && model->getOptionsModel()->getCoinControlFeatures())
        CoinControlDialog::coinControl()->nCoinType = index+1;
};

// Coin Control: settings menu - coin control enabled/disabled by user
void SendCoinsDialog::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked);

    if (!checked && model) // coin control features disabled
        CoinControlDialog::coinControl()->SetNull();

    coinControlUpdateLabels();
}

// Coin Control: button inputs -> show actual coin control dialog
void SendCoinsDialog::coinControlButtonClicked()
{
    CoinControlDialog dlg(platformStyle);
    dlg.setModel(model);
    dlg.exec();
    coinControlUpdateLabels();
}

// Coin Control: checkbox custom change address
void SendCoinsDialog::coinControlChangeChecked(int state)
{
    if (state == Qt::Unchecked)
    {
        CoinControlDialog::coinControl()->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->clear();
    }
    else
        // use this to re-validate an already entered address
        coinControlChangeEdited(ui->lineEditCoinControlChange->text());

    ui->lineEditCoinControlChange->setEnabled((state == Qt::Checked));
}

// Coin Control: custom change address changed
void SendCoinsDialog::coinControlChangeEdited(const QString& text)
{
    if (model && model->getAddressTableModel())
    {
        // Default to no change address until verified
        CoinControlDialog::coinControl()->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");

        const CTxDestination dest = DecodeDestination(text.toStdString());

        if (text.isEmpty()) // Nothing entered
        {
            ui->labelCoinControlChangeLabel->setText("");
        }
        else if (!IsValidDestination(dest)) // Invalid address
        {
            ui->labelCoinControlChangeLabel->setText(tr("Warning: Invalid Ghost address"));
        }
        else // Valid address
        {
            //if (!model->wallet().isSpendable(dest)) {
            if (!model->wallet().ownDestination(dest)) // Unknown change address
            {
                ui->labelCoinControlChangeLabel->setText(tr("Warning: Unknown change address"));

                // confirmation dialog
                QMessageBox::StandardButton btnRetVal = QMessageBox::question(this, tr("Confirm custom change address"), tr("The address you selected for change is not part of this wallet. Any or all funds in your wallet may be sent to this address. Are you sure?"),
                    QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);

                if(btnRetVal == QMessageBox::Yes)
                    CoinControlDialog::coinControl()->destChange = dest;
                else
                {
                    ui->lineEditCoinControlChange->setText("");
                    ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");
                    ui->labelCoinControlChangeLabel->setText("");
                }
            }
            else // Known change address
            {
                ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");

                // Query label
                QString associatedLabel = model->getAddressTableModel()->labelForAddress(text);
                if (!associatedLabel.isEmpty())
                    ui->labelCoinControlChangeLabel->setText(associatedLabel);
                else
                    ui->labelCoinControlChangeLabel->setText(tr("(no label)"));

                CoinControlDialog::coinControl()->destChange = dest;
            }
        }
    }
}

// Coin Control: update labels
void SendCoinsDialog::coinControlUpdateLabels()
{
    if (!model || !model->getOptionsModel())
        return;

    updateCoinControlState(*CoinControlDialog::coinControl());

    // set pay amounts
    CoinControlDialog::payAmounts.clear();
    CoinControlDialog::fSubtractFeeFromAmount = false;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry && !entry->isHidden())
        {
            SendCoinsRecipient rcp = entry->getValue();
            CoinControlDialog::payAmounts.append(rcp.amount);
            if (rcp.fSubtractFeeFromAmount)
                CoinControlDialog::fSubtractFeeFromAmount = true;
        }
    }

    if (CoinControlDialog::coinControl()->HasSelected())
    {
        // actual coin control calculation
        CoinControlDialog::updateLabels(model, this);

        // show coin control stats
        ui->labelCoinControlAutomaticallySelected->hide();
        ui->widgetCoinControl->show();
    }
    else
    {
        // hide coin control stats
        ui->labelCoinControlAutomaticallySelected->show();
        ui->widgetCoinControl->hide();
        ui->labelCoinControlInsuffFunds->hide();
    }
}

SendConfirmationDialog::SendConfirmationDialog(const QString& title, const QString& text, const QString& informative_text, const QString& detailed_text, int _secDelay, const QString& _confirmButtonText, QWidget* parent)
    : QMessageBox(parent), secDelay(_secDelay), confirmButtonText(_confirmButtonText)
{
    setIcon(QMessageBox::Question);
    setWindowTitle(title); // On macOS, the window title is ignored (as required by the macOS Guidelines).
    setText(text);
    setInformativeText(informative_text);
    setDetailedText(detailed_text);
    setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    setDefaultButton(QMessageBox::Cancel);
    yesButton = button(QMessageBox::Yes);
    updateYesButton();
    connect(&countDownTimer, &QTimer::timeout, this, &SendConfirmationDialog::countDown);
}

int SendConfirmationDialog::exec()
{
    updateYesButton();
    countDownTimer.start(1000);
    return QMessageBox::exec();
}

void SendConfirmationDialog::countDown()
{
    secDelay--;
    updateYesButton();

    if(secDelay <= 0)
    {
        countDownTimer.stop();
    }
}

void SendConfirmationDialog::updateYesButton()
{
    if(secDelay > 0)
    {
        yesButton->setEnabled(false);
        yesButton->setText(confirmButtonText + " (" + QString::number(secDelay) + ")");
    }
    else
    {
        yesButton->setEnabled(true);
        yesButton->setText(confirmButtonText);
    }
}
