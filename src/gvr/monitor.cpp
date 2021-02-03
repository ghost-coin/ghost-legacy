// Copyright (c) 2020 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gvr/monitor.h>
#include <gvr/payee.h>

//! internal state
int monitor_height{0};
int current_height{0};
int list_last_shown{0};
bool exiting{false};

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
    while (!exiting)
    {
       bool ibd = ::ChainstateActive().IsInitialBlockDownload();
       current_height = ::ChainActive().Height();
       if (monitor_height < current_height)
       {
           CBlock currentBlock;
           pindex = ::ChainActive()[monitor_height];
           bool valid = ReadBlockFromDisk(currentBlock, pindex, consensusParams);
           if (!valid) continue;
           for (const auto& tx : currentBlock.vtx) {
              int n = 0;
              for (const auto& txout : tx->vpout) {
                 if (txout->GetType() == OUTPUT_STANDARD)
                 {
                     CCoinsView viewDummy;
                     CCoinsViewCache view(&viewDummy);

                     LOCK(cs_main);
                     LOCK(mempool.cs);
                     CCoinsViewCache &viewChain = ::ChainstateActive().CoinsTip();
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

           //! set next height
           ++monitor_height;
           if (ibd && (monitor_height % 5 == 0))
               LogPrintf("monitor height %d\n", monitor_height);
           testCandidate(monitor_height-1);
       }

       //! display once per block at chain tip
       if (!ibd && (list_last_shown < monitor_height)) {
           printCandidates();
           list_last_shown = monitor_height;
       }

       //! dont burn out the processor
       if (!ibd) MilliSleep(10);
    }
}

