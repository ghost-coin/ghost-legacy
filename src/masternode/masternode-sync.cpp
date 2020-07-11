// Copyright (c) 2014-2020 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternode/activemasternode.h>
#include <init.h>
#include <validation.h>
#include <masternode/masternode-payments.h>
#include <masternode/masternode-sync.h>
#include <netfulfilledman.h>
#include <netmessagemaker.h>
#include <ui_interface.h>
#include <shutdown.h>
#include <evo/deterministicmns.h>

class CMasternodeSync;
CMasternodeSync masternodeSync;

void CMasternodeSync::Reset()
{
    nCurrentAsset = MASTERNODE_SYNC_INITIAL;
    nTriedPeerCount = 0;
    nTimeAssetSyncStarted = GetTime();
    nTimeLastBumped = GetTime();
    nTimeLastFailure = 0;
}

void CMasternodeSync::BumpAssetLastTime(const std::string& strFuncName)
{
    if(IsSynced() || IsFailed()) return;
    nTimeLastBumped = GetTime();
    LogPrint(BCLog::MASTERNODE, "CMasternodeSync::BumpAssetLastTime -- %s\n", strFuncName);
}

std::string CMasternodeSync::GetAssetName()
{
    switch(nCurrentAsset)
    {
        case(MASTERNODE_SYNC_INITIAL):      return "MASTERNODE_SYNC_INITIAL";
        case(MASTERNODE_SYNC_WAITING):      return "MASTERNODE_SYNC_WAITING";
        case(MASTERNODE_SYNC_FAILED):       return "MASTERNODE_SYNC_FAILED";
        case MASTERNODE_SYNC_FINISHED:      return "MASTERNODE_SYNC_FINISHED";
        default:                            return "UNKNOWN";
    }
}

void CMasternodeSync::SwitchToNextAsset(CConnman& connman)
{
    switch(nCurrentAsset)
    {
        case(MASTERNODE_SYNC_FAILED):
            throw std::runtime_error("Can't switch to next asset from failed, should use Reset() first!");
            break;
        case(MASTERNODE_SYNC_INITIAL):
            nCurrentAsset = MASTERNODE_SYNC_WAITING;
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(MASTERNODE_SYNC_WAITING):
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nCurrentAsset = MASTERNODE_SYNC_FINISHED;
            uiInterface.NotifyAdditionalDataSyncProgressChanged(1);

            connman.ForEachNode([](CNode* pnode) {
                netfulfilledman.AddFulfilledRequest(pnode->addr, "full-sync");
            });
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Sync has finished\n");

            break;
    }
    nTriedPeerCount = 0;
    nTimeAssetSyncStarted = GetTime();
    BumpAssetLastTime("CMasternodeSync::SwitchToNextAsset");
}

std::string CMasternodeSync::GetSyncStatus()
{
    switch (masternodeSync.nCurrentAsset) {
        case MASTERNODE_SYNC_INITIAL:       return ("Synchronizing blockchain...");
        case MASTERNODE_SYNC_WAITING:       return ("Synchronization pending...");
        case MASTERNODE_SYNC_FAILED:        return ("Synchronization failed");
        case MASTERNODE_SYNC_FINISHED:      return ("Synchronization finished");
        default:                            return "";
    }
}

void CMasternodeSync::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == NetMsgType::SYNCSTATUSCOUNT) { //Sync status count

        //do not care about stats if sync process finished or failed
        if(IsSynced() || IsFailed()) return;

        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        LogPrintf("SYNCSTATUSCOUNT -- got inventory count: nItemID=%d  nCount=%d  peer=%d\n", nItemID, nCount, pfrom->GetId());
    }
}

void CMasternodeSync::ProcessTick(CConnman& connman)
{
    static int nTick = 0;
    nTick++;

    const static int64_t nSyncStart = GetTimeMillis();
    const static std::string strAllow = strprintf("allow-sync-%lld", nSyncStart);

    // reset the sync process if the last call to this function was more than 60 minutes ago (client was in sleep mode)
    static int64_t nTimeLastProcess = GetTime();
    if(GetTime() - nTimeLastProcess > 60*60 && !fMasternodeMode) {
        LogPrintf("CMasternodeSync::ProcessTick -- WARNING: no actions for too long, restarting sync...\n");
        Reset();
        SwitchToNextAsset(connman);
        nTimeLastProcess = GetTime();
        return;
    }

    if(GetTime() - nTimeLastProcess < MASTERNODE_SYNC_TICK_SECONDS) {
        // too early, nothing to do here
        return;
    }

    nTimeLastProcess = GetTime();

    // reset sync status in case of any other sync failure
    if(IsFailed()) {
        if(nTimeLastFailure + (1*60) < GetTime()) { // 1 minute cooldown after failed sync
            LogPrintf("CMasternodeSync::ProcessTick -- WARNING: failed to sync, trying again...\n");
            Reset();
            SwitchToNextAsset(connman);
        }
        return;
    }

    // gradually request the rest of the votes after sync finished
    if(IsSynced()) {
        std::vector<CNode*> vNodesCopy = connman.CopyNodeVector(CConnman::FullyConnectedOnly);
        connman.ReleaseNodeVector(vNodesCopy);
        return;
    }

    // Calculate "progress" for LOG reporting / GUI notification
    double nSyncProgress = double(nTriedPeerCount + (nCurrentAsset - 1) * 8) / (8*4);
    LogPrintf("CMasternodeSync::ProcessTick -- nTick %d nCurrentAsset %d nTriedPeerCount %d nSyncProgress %f\n", nTick, nCurrentAsset, nTriedPeerCount, nSyncProgress);
    uiInterface.NotifyAdditionalDataSyncProgressChanged(nSyncProgress);

    std::vector<CNode*> vNodesCopy = connman.CopyNodeVector(CConnman::FullyConnectedOnly);

    for (auto& pnode : vNodesCopy)
    {
        CNetMsgMaker msgMaker(pnode->GetSendVersion());

        // Don't try to sync any data from outbound "masternode" connections -
        // they are temporary and should be considered unreliable for a sync process.
        // Inbound connection this early is most likely a "masternode" connection
        // initiated from another node, so skip it too.
        if(pnode->fMasternode || (fMasternodeMode && pnode->fInbound)) continue;

        // QUICK MODE (REGTEST ONLY!)
        if(Params().NetworkIDString() == CBaseChainParams::REGTEST)
        {
            if (nCurrentAsset == MASTERNODE_SYNC_WAITING) {
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETSPORKS)); //get current network sporks
                SwitchToNextAsset(connman);
            }
            connman.ReleaseNodeVector(vNodesCopy);
            return;
        }

        // NORMAL NETWORK MODE - TESTNET/MAINNET
        {
            if ((pnode->m_legacyWhitelisted || pnode->m_manual_connection) && !netfulfilledman.HasFulfilledRequest(pnode->addr, strAllow)) {
                netfulfilledman.RemoveAllFulfilledRequests(pnode->addr);
                netfulfilledman.AddFulfilledRequest(pnode->addr, strAllow);
                LogPrintf("CMasternodeSync::ProcessTick -- skipping mnsync restrictions for peer=%d\n", pnode->GetId());
            }

            if(netfulfilledman.HasFulfilledRequest(pnode->addr, "full-sync")) {
                // We already fully synced from this node recently,
                // disconnect to free this connection slot for another peer.
                pnode->fDisconnect = true;
                LogPrintf("CMasternodeSync::ProcessTick -- disconnecting from recently synced peer=%d\n", pnode->GetId());
                continue;
            }

            // SPORK : ALWAYS ASK FOR SPORKS AS WE SYNC

            if(!netfulfilledman.HasFulfilledRequest(pnode->addr, "spork-sync")) {
                // always get sporks first, only request once from each peer
                netfulfilledman.AddFulfilledRequest(pnode->addr, "spork-sync");
                // get current network sporks
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETSPORKS));
                LogPrintf("CMasternodeSync::ProcessTick -- nTick %d nCurrentAsset %d -- requesting sporks from peer=%d\n", nTick, nCurrentAsset, pnode->GetId());
            }

            // INITIAL TIMEOUT

            if(nCurrentAsset == MASTERNODE_SYNC_WAITING) {
                if (!pnode->fInbound && !netfulfilledman.HasFulfilledRequest(pnode->addr, "mempool-sync")) {
                    netfulfilledman.AddFulfilledRequest(pnode->addr, "mempool-sync");
                    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::MEMPOOL));
                    LogPrintf("CMasternodeSync::ProcessTick -- nTick %d nCurrentAsset %d -- syncing mempool from peer=%d\n", nTick, nCurrentAsset, pnode->GetId());
                }

                if(GetTime() - nTimeLastBumped > MASTERNODE_SYNC_TIMEOUT_SECONDS) {
                    // At this point we know that:
                    // a) there are peers (because we are looping on at least one of them);
                    // b) we waited for at least MASTERNODE_SYNC_TIMEOUT_SECONDS since we reached
                    //    the headers tip the last time (i.e. since we switched from
                    //     MASTERNODE_SYNC_INITIAL to MASTERNODE_SYNC_WAITING and bumped time);
                    // c) there were no blocks (UpdatedBlockTip, NotifyHeaderTip) or headers (AcceptedBlockHeader)
                    //    for at least MASTERNODE_SYNC_TIMEOUT_SECONDS.
                    // We must be at the tip already, let's move to the next asset.
                    SwitchToNextAsset(connman);
                }
            }
        }
    }
    // looped through all nodes, release them
    connman.ReleaseNodeVector(vNodesCopy);
}

void CMasternodeSync::AcceptedBlockHeader(const CBlockIndex *pindexNew)
{
    LogPrint(BCLog::MASTERNODE, "CMasternodeSync::AcceptedBlockHeader -- pindexNew->nHeight: %d\n", pindexNew->nHeight);

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block header arrives while we are still syncing blockchain
        BumpAssetLastTime("CMasternodeSync::AcceptedBlockHeader");
    }
}

void CMasternodeSync::NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint(BCLog::MASTERNODE, "CMasternodeSync::NotifyHeaderTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CMasternodeSync::NotifyHeaderTip");
    }
}

void CMasternodeSync::UpdatedBlockTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint(BCLog::MASTERNODE, "CMasternodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CMasternodeSync::UpdatedBlockTip");
    }

    if (fInitialDownload) {
        // switched too early
        if (IsBlockchainSynced()) {
            Reset();
        }

        // no need to check any further while still in IBD mode
        return;
    }

    // Note: since we sync headers first, it should be ok to use this
    static bool fReachedBestHeader = false;
    bool fReachedBestHeaderNew = pindexNew->GetBlockHash() == pindexBestHeader->GetBlockHash();

    if (fReachedBestHeader && !fReachedBestHeaderNew) {
        // Switching from true to false means that we previousely stuck syncing headers for some reason,
        // probably initial timeout was not enough,
        // because there is no way we can update tip not having best header
        Reset();
        fReachedBestHeader = false;
        return;
    }

    fReachedBestHeader = fReachedBestHeaderNew;

    LogPrint(BCLog::MASTERNODE, "CMasternodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d pindexBestHeader->nHeight: %d fInitialDownload=%d fReachedBestHeader=%d\n",
                pindexNew->nHeight, pindexBestHeader->nHeight, fInitialDownload, fReachedBestHeader);

    if (!IsBlockchainSynced() && fReachedBestHeader) {
        // Reached best header while being in initial mode.
        // We must be at the tip already, let's move to the next asset.
        SwitchToNextAsset(connman);
    }
}

void CMasternodeSync::DoMaintenance(CConnman &connman)
{
    if (ShutdownRequested()) return;

    ProcessTick(connman);
}
