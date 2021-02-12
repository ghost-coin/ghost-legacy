// Copyright (c) 2020 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GVR_MONITOR_H
#define GVR_MONITOR_H

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <index/txindex.h>
#include <validation.h>

void monitorThread();
extern bool index_ready;
void blockWorker(CBlockIndex* pindex, const Consensus::Params& consensusParams);

#endif // GVR_MONITOR_H

