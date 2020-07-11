// Copyright (c) 2014-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternode/activemasternode.h>
#include <consensus/validation.h>
#include <init.h>
#include <masternode/masternode-payments.h>
#include <masternode/masternode-sync.h>
#include <messagesigner.h>
#include <netfulfilledman.h>
#include <netmessagemaker.h>
#include <spork.h>
#include <validation.h>

#include <string>

CMasternodePayments mnpayments;

bool IsOldBudgetBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string& strErrorRet) {
    bool isBlockRewardValueMet = (block.vtx[0]->GetValueOut() <= blockReward);
    return isBlockRewardValueMet;
}

/**
* IsBlockValueValid
*
*   Determine if coinbase outgoing created money is the correct value
*
*   Why is this needed?
*   - In Dash some blocks are superblocks, which output much higher amounts of coins
*   - Otherblocks are 10% lower in outgoing value, so in total, no extra coins are created
*   - When non-superblocks are detected, the normal schedule should be maintained
*/

bool IsBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string& strErrorRet) {
    bool isBlockRewardValueMet = (block.vtx[0]->GetValueOut() <= blockReward);
    return isBlockRewardValueMet;
}

bool IsBlockPayeeValid(const CTransaction& txNew, int nBlockHeight, CAmount blockReward)
{
    // Check for correct masternode payment
    if(mnpayments.IsTransactionValid(txNew, nBlockHeight, blockReward)) {
        LogPrintf("%s -- Valid masternode payment at height %d: %s", __func__, nBlockHeight, txNew.ToString());
        return true;
    }

    LogPrintf("%s -- ERROR: Invalid masternode payment detected at height %d: %s", __func__, nBlockHeight, txNew.ToString()); /* Continued */
    return false;
}

void FillBlockPayments(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& voutMasternodePaymentsRet, std::vector<CTxOut>& voutSuperblockPaymentsRet)
{
    if (!mnpayments.GetMasternodeTxOuts(nBlockHeight, blockReward, voutMasternodePaymentsRet)) {
        LogPrintf("%s -- no masternode to pay (MN list probably empty)\n", __func__);
    }

    txNew.vout.insert(txNew.vout.end(), voutMasternodePaymentsRet.begin(), voutMasternodePaymentsRet.end());
    txNew.vout.insert(txNew.vout.end(), voutSuperblockPaymentsRet.begin(), voutSuperblockPaymentsRet.end());

    std::string voutMasternodeStr;
    for (const auto& txout : voutMasternodePaymentsRet) {
        // subtract MN payment from miner reward
        txNew.vout[0].nValue -= txout.nValue;
        if (!voutMasternodeStr.empty())
            voutMasternodeStr += ",";
        voutMasternodeStr += txout.ToString();
    }

    LogPrintf("%s -- nBlockHeight %d blockReward %lld voutMasternodePaymentsRet \"%s\" txNew %s", __func__,
              nBlockHeight, blockReward, voutMasternodeStr, txNew.ToString());
}

std::string GetRequiredPaymentsString(int nBlockHeight, const CDeterministicMNCPtr &payee)
{
    std::string strPayee = "Unknown";
    if (payee) {
        CTxDestination dest;
        if (!ExtractDestination(payee->pdmnState->scriptPayout, dest))
            assert(false);
        strPayee = EncodeDestination(dest);
    }
    return strPayee;
}

std::map<int, std::string> GetRequiredPaymentsStrings(int nStartHeight, int nEndHeight)
{
    std::map<int, std::string> mapPayments;

    if (nStartHeight < 1) {
        nStartHeight = 1;
    }

    LOCK(cs_main);
    int nChainTipHeight = ::ChainActive().Height();

    bool doProjection = false;
    for(int h = nStartHeight; h < nEndHeight; h++) {
        if (h <= nChainTipHeight) {
            auto payee = deterministicMNManager->GetListForBlock(::ChainActive()[h - 1]).GetMNPayee();
            mapPayments.emplace(h, GetRequiredPaymentsString(h, payee));
        } else {
            doProjection = true;
            break;
        }
    }
    if (doProjection) {
        auto projection = deterministicMNManager->GetListAtChainTip().GetProjectedMNPayees(nEndHeight - nChainTipHeight);
        for (size_t i = 0; i < projection.size(); i++) {
            auto payee = projection[i];
            int h = nChainTipHeight + 1 + i;
            mapPayments.emplace(h, GetRequiredPaymentsString(h, payee));
        }
    }

    return mapPayments;
}

/**
*   GetMasternodeTxOuts
*
*   Get masternode payment tx outputs
*/

bool CMasternodePayments::GetMasternodeTxOuts(int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& voutMasternodePaymentsRet) const
{
    // make sure it's not filled yet
    voutMasternodePaymentsRet.clear();

    if(!GetBlockTxOuts(nBlockHeight, blockReward, voutMasternodePaymentsRet)) {
        LogPrintf("CMasternodePayments::%s -- no payee (deterministic masternode list empty)\n", __func__);
        return false;
    }

    for (const auto& txout : voutMasternodePaymentsRet) {
        CTxDestination dest;
        ExtractDestination(txout.scriptPubKey, dest);

        LogPrintf("CMasternodePayments::%s -- Masternode payment %lld to %s\n", __func__, txout.nValue, EncodeDestination(dest));
    }

    return true;
}

bool CMasternodePayments::GetBlockTxOuts(int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& voutMasternodePaymentsRet) const
{
    voutMasternodePaymentsRet.clear();

    CAmount masternodeReward = GetMasternodePayment(nBlockHeight, blockReward);

    const CBlockIndex* pindex;
    {
        LOCK(cs_main);
        pindex = ::ChainActive()[nBlockHeight - 1];
    }
    uint256 proTxHash;
    auto dmnPayee = deterministicMNManager->GetListForBlock(pindex).GetMNPayee();
    if (!dmnPayee) {
        return false;
    }

    CAmount operatorReward = 0;
    if (dmnPayee->nOperatorReward != 0 && dmnPayee->pdmnState->scriptOperatorPayout != CScript()) {
        // This calculation might eventually turn out to result in 0 even if an operator reward percentage is given.
        // This will however only happen in a few years when the block rewards drops very low.
        operatorReward = (masternodeReward * dmnPayee->nOperatorReward) / 10000;
        masternodeReward -= operatorReward;
    }

    if (masternodeReward > 0) {
        voutMasternodePaymentsRet.emplace_back(masternodeReward, dmnPayee->pdmnState->scriptPayout);
    }
    if (operatorReward > 0) {
        voutMasternodePaymentsRet.emplace_back(operatorReward, dmnPayee->pdmnState->scriptOperatorPayout);
    }

    return true;
}

bool CMasternodePayments::IsTransactionValid(const CTransaction& txNew, int nBlockHeight, CAmount blockReward) const
{
    if (!deterministicMNManager->IsDIP3Enforced(nBlockHeight)) {
        // can't verify historical blocks here
        return true;
    }

    std::vector<CTxOut> voutMasternodePayments;
    if (!GetBlockTxOuts(nBlockHeight, blockReward, voutMasternodePayments)) {
        LogPrintf("CMasternodePayments::%s -- ERROR failed to get payees for block at height %s\n", __func__, nBlockHeight);
        return true;
    }

    for (const auto& txout : voutMasternodePayments) {
        bool found = false;
        for (const auto& txout2 : txNew.vout) {
            if (txout == txout2) {
                found = true;
                break;
            }
        }
        if (!found) {
            CTxDestination dest;
            if (!ExtractDestination(txout.scriptPubKey, dest))
                assert(false);
            LogPrintf("CMasternodePayments::%s -- ERROR failed to find expected payee %s in block at height %s\n", __func__, EncodeDestination(dest), nBlockHeight);
            return false;
        }
    }
    return true;
}
