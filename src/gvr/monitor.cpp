// Copyright (c) 2020 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gvr/monitor.h>
#include <gvr/payee.h>
#include <gvr/pool.h>

//! internal state
bool index_ready{false};
int monitor_height{0};
int current_height{0};

void consensusWorker(CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    int height = pindex->nHeight;

    if (gvrPaymentsActive(height)) {
        LogPrintf("%s - gvrPaymentsActive @ height %d\n", __func__, height);
    }

    if (gvrPaymentsEnforced(height)) {
        LogPrintf("%s - gvrPaymentsActive @ height %d\n", __func__, height);
    }
}

void blockWorker(CBlockIndex* pindex, const Consensus::Params& consensusParams, bool verify)
{
    CBlock currentBlock;
    bool valid = ReadBlockFromDisk(currentBlock, pindex, consensusParams);
    if (!valid)
        return;
    if (verify)
        consensusWorker(pindex, consensusParams);
    for (const auto& tx : currentBlock.vtx) {
        int n = 0;
        for (const auto& txout : tx->vpout) {
            if (txout->GetType() == OUTPUT_STANDARD) {
                CCoinsView viewDummy;
                CCoinsViewCache view(&viewDummy);

                LOCK(cs_main);
                LOCK(mempool.cs);
                CCoinsViewCache& viewChain = ::ChainstateActive().CoinsTip();
                CCoinsViewMemPool viewMempool(&viewChain, mempool);
                view.SetBackend(viewMempool);

                //! pull candidate details
                auto payee = COutPoint(tx->GetHash(), n);
                const Coin& coin = view.AccessCoin(payee);
                const CScript& payeeScript = coin.out.scriptPubKey;
                if (!coin.IsSpent()) {
                    incomingCandidate(payee, txout->GetValue(), payeeScript, monitor_height);
                }
                view.SetBackend(viewDummy);
            }
            ++n;
        }
    }
}

void monitorThread()
{
    const Consensus::Params& consensusParams = Params().GetConsensus();

    //! begin at genesis pindex
    CBlockIndex* pindex = ::ChainActive().Tip();
    while (pindex->nHeight != 0) {
        pindex = pindex->pprev;
    }
    monitor_height = pindex->nHeight;

    //! follow the chain
    while (monitor_height < ::ChainActive().Tip()->nHeight) {
        current_height = ::ChainActive().Height();
        if (monitor_height < current_height) {
            pindex = ::ChainActive()[monitor_height];
            blockWorker(pindex, consensusParams);

            //! set next height
            ++monitor_height;
            testCandidate(monitor_height - 1);
        }
    }

    LogPrintf("%s - Initial index has completed (last block %d)\n", __func__, monitor_height);
    index_ready = true;
}
