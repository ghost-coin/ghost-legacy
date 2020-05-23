// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <checkqueue.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <cuckoocache.h>
#include <flatfile.h>
#include <hash.h>
#include <index/txindex.h>
#include <logging.h>
#include <logging/timer.h>
#include <optional.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <reverse_iterator.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <script/sigcache.h>
#include <shutdown.h>
#include <timedata.h>
#include <tinyformat.h>
#include <txdb.h>
#include <txmempool.h>
#include <ui_interface.h>
#include <uint256.h>
#include <undo.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/translation.h>
#include <validationinterface.h>
#include <warnings.h>
#include <smsg/smessage.h>
#include <net.h>
#include <pos/kernel.h>
#include <anon.h>
#include <rctindex.h>
#include <insight/insight.h>

#include <string>

#include <boost/algorithm/string/replace.hpp>
#include <boost/thread.hpp>

#if defined(NDEBUG)
# error "Ghost cannot be compiled without assertions."
#endif

#define MICRO 0.000001
#define MILLI 0.001

/**
 * An extra transaction can be added to a package, as long as it only has one
 * ancestor and is no larger than this. Not really any reason to make this
 * configurable as it doesn't materially change DoS parameters.
 */
static const unsigned int EXTRA_DESCENDANT_TX_SIZE_LIMIT = 10000;
/** Maximum kilobytes for transactions to store for processing during reorg */
static const unsigned int MAX_DISCONNECTED_TX_POOL_SIZE = 20000;
/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB
/** Time to wait (in seconds) between writing blocks/block index to disk. */
static const unsigned int DATABASE_WRITE_INTERVAL = 60 * 60;
/** Time to wait (in seconds) between flushing chainstate to disk. */
static const unsigned int DATABASE_FLUSH_INTERVAL = 24 * 60 * 60;
/** Maximum age of our tip in seconds for us to be considered current for fee estimation */
static const int64_t MAX_FEE_ESTIMATION_TIP_AGE = 3 * 60 * 60;

bool CBlockIndexWorkComparator::operator()(const CBlockIndex *pa, const CBlockIndex *pb) const {
    // First sort by most total work, ...
    if (pa->nChainWork > pb->nChainWork) return false;
    if (pa->nChainWork < pb->nChainWork) return true;

    // ... then by earliest time received, ...
    if (pa->nSequenceId < pb->nSequenceId) return false;
    if (pa->nSequenceId > pb->nSequenceId) return true;

    // Use pointer address as tie breaker (should only happen with blocks
    // loaded from disk, as those all have id 0).
    if (pa < pb) return false;
    if (pa > pb) return true;

    // Identical blocks.
    return false;
}

ChainstateManager g_chainman;

CChainState& ChainstateActive()
{
    LOCK(::cs_main);
    assert(g_chainman.m_active_chainstate);
    return *g_chainman.m_active_chainstate;
}

CChain& ChainActive()
{
    LOCK(::cs_main);
    return ::ChainstateActive().m_chain;
}

/**
 * Mutex to guard access to validation specific variables, such as reading
 * or changing the chainstate.
 *
 * This may also need to be locked when updating the transaction pool, e.g. on
 * AcceptToMemoryPool. See CTxMemPool::cs comment for details.
 *
 * The transaction pool has a separate lock to allow reading from it and the
 * chainstate at the same time.
 */
RecursiveMutex cs_main;

std::map<uint256, StakeConflict> mapStakeConflict;
std::map<COutPoint, uint256> mapStakeSeen;
std::list<COutPoint> listStakeSeen;

CoinStakeCache coinStakeCache GUARDED_BY(cs_main);
std::set<CCmpPubKey> setConnectKi; // hacky workaround

CBlockIndex *pindexBestHeader = nullptr;
Mutex g_best_block_mutex;
std::condition_variable g_best_block_cv;
uint256 g_best_block;
bool g_parallel_script_checks{false};
std::atomic_bool fImporting(false);
std::atomic_bool fReindex(false);
std::atomic_bool fSkipRangeproof(false);
std::atomic_bool fBusyImporting(false);        // covers ActivateBestChain too
bool fHavePruned = false;
bool fPruneMode = false;
bool fRequireStandard = true;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;
unsigned int MIN_BLOCKS_TO_KEEP = 288;
unsigned int NODE_NETWORK_LIMITED_MIN_BLOCKS = 288;
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;
static bool fVerifyingDB = false;

uint256 hashAssumeValid;
arith_uint256 nMinimumChainWork;

CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);

CBlockPolicyEstimator feeEstimator;
CTxMemPool mempool(&feeEstimator);

// Internal stuff
namespace {
    CBlockIndex* pindexBestInvalid = nullptr;

    RecursiveMutex cs_LastBlockFile;
    std::vector<CBlockFileInfo> vinfoBlockFile;
    int nLastBlockFile = 0;
    /** Global flag to indicate we should check to see if there are
     *  block/undo files that should be deleted.  Set on startup
     *  or if we allocate more file space when we're in prune mode
     */
    bool fCheckForPruning = false;

    /** Dirty block index entries. */
    std::set<CBlockIndex*> setDirtyBlockIndex;

    /** Dirty block file entries. */
    std::set<int> setDirtyFileInfo;
} // anon namespace

int StakeConflict::Add(NodeId id)
{
    nLastUpdated = GetAdjustedTime();
    std::pair<std::map<NodeId, int>::iterator,bool> ret;
    ret = peerCount.insert(std::pair<NodeId, int>(id, 1));
    if (ret.second == false) // existing element
        ret.first->second++;

    return 0;
};

CBlockIndex* LookupBlockIndex(const uint256& hash)
{
    AssertLockHeld(cs_main);
    BlockMap::const_iterator it = g_chainman.BlockIndex().find(hash);
    return it == g_chainman.BlockIndex().end() ? nullptr : it->second;
}

CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator)
{
    AssertLockHeld(cs_main);

    // Find the latest block common to locator and chain - we expect that
    // locator.vHave is sorted descending by height.
    for (const uint256& hash : locator.vHave) {
        CBlockIndex* pindex = LookupBlockIndex(hash);
        if (pindex) {
            if (chain.Contains(pindex))
                return pindex;
            if (pindex->GetAncestor(chain.Height()) == chain.Tip()) {
                return chain.Tip();
            }
        }
    }
    return chain.Genesis();
}

std::unique_ptr<CBlockTreeDB> pblocktree;

// See definition for documentation
static void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight);
static void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight);
bool CheckInputScripts(const CTransaction& tx, TxValidationState &state, const CCoinsViewCache &inputs, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks = nullptr, bool fAnonChecks = true);
static FILE* OpenUndoFile(const FlatFilePos &pos, bool fReadOnly = false);
static FlatFileSeq BlockFileSeq();
static FlatFileSeq UndoFileSeq();

bool CheckFinalTx(const CTransaction &tx, int flags)
{
    AssertLockHeld(cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses ::ChainActive().Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than ::ChainActive().Height().
    const int nBlockHeight = ::ChainActive().Height() + 1;

    // BIP113 requires that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST)
                             ? ::ChainActive().Tip()->GetMedianTimePast()
                             : GetAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}


bool TestLockPointValidity(const LockPoints* lp)
{
    AssertLockHeld(cs_main);
    assert(lp);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock) {
        // Check whether ::ChainActive() is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!::ChainActive().Contains(lp->maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTxMemPool& pool, const CTransaction& tx, int flags, LockPoints* lp, bool useExistingLockPoints)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pool.cs);

    CBlockIndex* tip = ::ChainActive().Tip();
    assert(tip != nullptr);

    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses ::ChainActive().Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than ::ChainActive().Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        // CoinsTip() contains the UTXO set for ::ChainActive().Tip()
        CCoinsViewMemPool viewMemPool(&::ChainstateActive().CoinsTip(), pool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];

            if (txin.IsAnonInput())
            {
                prevheights[txinIndex] = tip->nHeight + 1;
                continue;
            };

            Coin coin;
            if (!viewMemPool.GetCoin(txin.prevout, coin)) {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coin.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            for (const int height : prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}

// Returns the script flags which should be checked for a given block
static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& chainparams);

static void LimitMempoolSize(CTxMemPool& pool, size_t limit, std::chrono::seconds age)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs, ::cs_main)
{
    int expired = pool.Expire(GetTime<std::chrono::seconds>() - age);
    if (expired != 0) {
        LogPrint(BCLog::MEMPOOL, "Expired %i transactions from the memory pool\n", expired);
    }

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    for (const COutPoint& removed : vNoSpendsRemaining)
        ::ChainstateActive().CoinsTip().Uncache(removed);
}

static bool IsCurrentForFeeEstimation() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    if (::ChainstateActive().IsInitialBlockDownload())
        return false;
    if (::ChainActive().Tip()->GetBlockTime() < (GetTime() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (::ChainActive().Height() < pindexBestHeader->nHeight - 1)
        return false;
    return true;
}

/* Make mempool consistent after a reorg, by re-adding or recursively erasing
 * disconnected block transactions from the mempool, and also removing any
 * other transactions from the mempool that are no longer valid given the new
 * tip/height.
 *
 * Note: we assume that disconnectpool only contains transactions that are NOT
 * confirmed in the current chain nor already in the mempool (otherwise,
 * in-mempool descendants of such transactions would be removed).
 *
 * Passing fAddToMempool=false will skip trying to add the transactions back,
 * and instead just erase from the mempool as needed.
 */

static void UpdateMempoolForReorg(DisconnectedBlockTransactions& disconnectpool, bool fAddToMempool) EXCLUSIVE_LOCKS_REQUIRED(cs_main, ::mempool.cs)
{
    AssertLockHeld(cs_main);
    std::vector<uint256> vHashUpdate;
    // disconnectpool's insertion_order index sorts the entries from
    // oldest to newest, but the oldest entry will be the last tx from the
    // latest mined block that was disconnected.
    // Iterate disconnectpool in reverse, so that we add transactions
    // back to the mempool starting with the earliest transaction that had
    // been previously seen in a block.
    auto it = disconnectpool.queuedTx.get<insertion_order>().rbegin();
    while (it != disconnectpool.queuedTx.get<insertion_order>().rend()) {
        // ignore validation errors in resurrected transactions
        TxValidationState stateDummy;
        if (!fAddToMempool || (*it)->IsCoinBase() ||
            !AcceptToMemoryPool(mempool, stateDummy, *it,
                                nullptr /* plTxnReplaced */, true /* bypass_limits */, 0 /* nAbsurdFee */)) {
            // If the transaction doesn't make it in to the mempool, remove any
            // transactions that depend on it (which would now be orphans).
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
        } else if (mempool.exists((*it)->GetHash())) {
            vHashUpdate.push_back((*it)->GetHash());
        }
        ++it;
    }
    disconnectpool.queuedTx.clear();
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    mempool.UpdateTransactionsFromBlock(vHashUpdate);

    // We also need to remove any now-immature transactions
    mempool.removeForReorg(&::ChainstateActive().CoinsTip(), ::ChainActive().Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    // Re-limit mempool size, in case we added any transactions
    LimitMempoolSize(mempool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, std::chrono::hours{gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY)});
}

// Used to avoid mempool polluting consensus critical paths if CCoinsViewMempool
// were somehow broken and returning the wrong scriptPubKeys
static bool CheckInputsFromMempoolAndCache(const CTransaction& tx, TxValidationState& state, const CCoinsViewCache& view, const CTxMemPool& pool,
                 unsigned int flags, PrecomputedTransactionData& txdata) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);

    // pool.cs should be locked already, but go ahead and re-take the lock here
    // to enforce that mempool doesn't change between when we check the view
    // and when we actually call through to CheckInputScripts
    LOCK(pool.cs);

    assert(!tx.IsCoinBase());
    for (const CTxIn& txin : tx.vin) {
        if (txin.IsAnonInput())
            continue;
        const Coin& coin = view.AccessCoin(txin.prevout);

        // AcceptToMemoryPoolWorker has already checked that the coins are
        // available, so this shouldn't fail. If the inputs are not available
        // here then return false.
        if (coin.IsSpent()) return false;

        // Check equivalence for available inputs.
        const CTransactionRef& txFrom = pool.get(txin.prevout.hash);
        if (txFrom) {
            assert(txFrom->GetHash() == txin.prevout.hash);
            assert(txFrom->GetNumVOuts() > txin.prevout.n);
            if (txFrom->IsGhostVersion()) {
                assert(coin.Matches(txFrom->vpout[txin.prevout.n].get()));
            } else {
                assert(txFrom->vout[txin.prevout.n] == coin.out);
            }
        } else {
            const Coin& coinFromDisk = ::ChainstateActive().CoinsTip().AccessCoin(txin.prevout);
            assert(!coinFromDisk.IsSpent());
            assert(coinFromDisk.out == coin.out);
        }
    }

    // Call CheckInputScripts() to cache signature and script validity against current tip consensus rules.
    return CheckInputScripts(tx, state, view, flags, /* cacheSigStore = */ true, /* cacheFullSciptStore = */ true, txdata);
}

namespace {

class MemPoolAccept
{
public:
    MemPoolAccept(CTxMemPool& mempool) : m_pool(mempool), m_view(&m_dummy), m_viewmempool(&::ChainstateActive().CoinsTip(), m_pool),
        m_limit_ancestors(gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT)),
        m_limit_ancestor_size(gArgs.GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000),
        m_limit_descendants(gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT)),
        m_limit_descendant_size(gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000) {}

    // We put the arguments we're handed into a struct, so we can pass them
    // around easier.
    struct ATMPArgs {
        const CChainParams& m_chainparams;
        TxValidationState &m_state;
        const int64_t m_accept_time;
        std::list<CTransactionRef>* m_replaced_transactions;
        const bool m_bypass_limits;
        const CAmount& m_absurd_fee;
        /*
         * Return any outpoints which were not previously present in the coins
         * cache, but were added as a result of validating the tx for mempool
         * acceptance. This allows the caller to optionally remove the cache
         * additions if the associated transaction ends up being rejected by
         * the mempool.
         */
        std::vector<COutPoint>& m_coins_to_uncache;
        const bool m_test_accept;
        const bool m_ignore_locks;
    };

    // Single transaction acceptance
    bool AcceptSingleTransaction(const CTransactionRef& ptx, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

private:
    // All the intermediate state that gets passed between the various levels
    // of checking a given transaction.
    struct Workspace {
        Workspace(const CTransactionRef& ptx) : m_ptx(ptx), m_hash(ptx->GetHash()) {}
        std::set<uint256> m_conflicts;
        CTxMemPool::setEntries m_all_conflicting;
        CTxMemPool::setEntries m_ancestors;
        std::unique_ptr<CTxMemPoolEntry> m_entry;

        bool m_replacement_transaction;
        CAmount m_modified_fees;
        CAmount m_conflicting_fees;
        size_t m_conflicting_size;

        const CTransactionRef& m_ptx;
        const uint256& m_hash;
    };

    // Run the policy checks on a given transaction, excluding any script checks.
    // Looks up inputs, calculates feerate, considers replacement, evaluates
    // package limits, etc. As this function can be invoked for "free" by a peer,
    // only tests that are fast should be done here (to avoid CPU DoS).
    bool PreChecks(ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Run the script checks using our policy flags. As this can be slow, we should
    // only invoke this on transactions that have otherwise passed policy checks.
    bool PolicyScriptChecks(ATMPArgs& args, Workspace& ws, PrecomputedTransactionData& txdata) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Re-run the script checks, using consensus flags, and try to cache the
    // result in the scriptcache. This should be done after
    // PolicyScriptChecks(). This requires that all inputs either be in our
    // utxo set or in the mempool.
    bool ConsensusScriptChecks(ATMPArgs& args, Workspace& ws, PrecomputedTransactionData &txdata) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Try to add the transaction to the mempool, removing any conflicts first.
    // Returns true if the transaction is in the mempool after any size
    // limiting is performed, false otherwise.
    bool Finalize(ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Compare a package's feerate against minimum allowed.
    bool CheckFeeRate(size_t package_size, CAmount package_fee, TxValidationState& state)
    {
        CAmount mempoolRejectFee = m_pool.GetMinFee(gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFee(package_size);
        if (state.m_has_anon_output) {
            mempoolRejectFee *= ANON_FEE_MULTIPLIER;
        }
        if (mempoolRejectFee > 0 && package_fee < mempoolRejectFee) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "mempool min fee not met", strprintf("%d < %d", package_fee, mempoolRejectFee));
        }

        if (package_fee < ::minRelayTxFee.GetFee(package_size)) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "min relay fee not met", strprintf("%d < %d", package_fee, ::minRelayTxFee.GetFee(package_size)));
        }
        return true;
    }

private:
    CTxMemPool& m_pool;
    CCoinsViewCache m_view;
    CCoinsViewMemPool m_viewmempool;
    CCoinsView m_dummy;

    // The package limits in effect at the time of invocation.
    const size_t m_limit_ancestors;
    const size_t m_limit_ancestor_size;
    // These may be modified while evaluating a transaction (eg to account for
    // in-mempool conflicts; see below).
    size_t m_limit_descendants;
    size_t m_limit_descendant_size;
};

bool MemPoolAccept::PreChecks(ATMPArgs& args, Workspace& ws)
{
    const CTransactionRef& ptx = ws.m_ptx;
    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;

    // Copy/alias what we need out of args
    TxValidationState &state = args.m_state;
    const int64_t nAcceptTime = args.m_accept_time;
    const bool bypass_limits = args.m_bypass_limits;
    const CAmount& nAbsurdFee = args.m_absurd_fee;
    std::vector<COutPoint>& coins_to_uncache = args.m_coins_to_uncache;

    // Alias what we need out of ws
    std::set<uint256>& setConflicts = ws.m_conflicts;
    CTxMemPool::setEntries& allConflicting = ws.m_all_conflicting;
    CTxMemPool::setEntries& setAncestors = ws.m_ancestors;
    std::unique_ptr<CTxMemPoolEntry>& entry = ws.m_entry;
    bool& fReplacementTransaction = ws.m_replacement_transaction;
    CAmount& nModifiedFees = ws.m_modified_fees;
    CAmount& nConflictingFees = ws.m_conflicting_fees;
    size_t& nConflictingSize = ws.m_conflicting_size;

    const Consensus::Params &consensus = Params().GetConsensus();
    state.SetStateInfo(nAcceptTime, ::ChainActive().Height(), consensus, fGhostMode, (fBusyImporting && fSkipRangeproof));

    if (!CheckTransaction(tx, state))
        return false; // state filled in by CheckTransaction

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "coinbase");

    // Coinstake is only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "coinstake");

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (fRequireStandard && !IsStandardTx(tx, reason, nAcceptTime))
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, reason);

    // Do not work on transactions that are too small.
    // A transaction with 1 segwit input and 1 P2WPHK output has non-witness size of 82 bytes.
    // Transactions smaller than this are not relayed to mitigate CVE-2017-12842 by not relaying
    // 64-byte transactions.
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) < (fGhostMode ? MIN_STANDARD_TX_NONWITNESS_SIZE_PART : MIN_STANDARD_TX_NONWITNESS_SIZE))
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "tx-size-small");

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!args.m_test_accept || !args.m_ignore_locks)
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-final");

    // is it already in the memory pool?
    if (m_pool.exists(hash)) {
        return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-in-mempool");
    }

    // Check for conflicts with in-memory transactions
    for (const CTxIn &txin : tx.vin)
    {
        if (txin.IsAnonInput()) {
            continue;
        }
        const CTransaction* ptxConflicting = m_pool.GetConflictTx(txin.prevout);
        if (ptxConflicting) {
            if (!setConflicts.count(ptxConflicting->GetHash()))
            {
                // Allow opt-out of transaction replacement by setting
                // nSequence > MAX_BIP125_RBF_SEQUENCE (SEQUENCE_FINAL-2) on all inputs.
                //
                // SEQUENCE_FINAL-1 is picked to still allow use of nLockTime by
                // non-replaceable transactions. All inputs rather than just one
                // is for the sake of multi-party protocols, where we don't
                // want a single party to be able to disable replacement.
                //
                // The opt-out ignores descendants as anyone relying on
                // first-seen mempool behavior should be checking all
                // unconfirmed ancestors anyway; doing otherwise is hopelessly
                // insecure.
                bool fReplacementOptOut = true;
                for (const CTxIn &_txin : ptxConflicting->vin)
                {
                    if (_txin.nSequence <= MAX_BIP125_RBF_SEQUENCE)
                    {
                        fReplacementOptOut = false;
                        break;
                    }
                }
                if (fReplacementOptOut) {
                    return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "txn-mempool-conflict");
                }

                setConflicts.insert(ptxConflicting->GetHash());
            }
        }
    }

    LockPoints lp;
    m_view.SetBackend(m_viewmempool);

    state.m_has_anon_input = false;
    CCoinsViewCache& coins_cache = ::ChainstateActive().CoinsTip();
    // do all inputs exist?
    for (const CTxIn& txin : tx.vin) {
        if (txin.IsAnonInput()) {
            state.m_has_anon_input = true;
            continue;
        }
        if (!coins_cache.HaveCoinInCache(txin.prevout)) {
            coins_to_uncache.push_back(txin.prevout);
        }

        // Note: this call may add txin.prevout to the coins cache
        // (coins_cache.cacheCoins) by way of FetchCoin(). It should be removed
        // later (via coins_to_uncache) if this tx turns out to be invalid.
        if (!m_view.HaveCoin(txin.prevout)) {
            // Are inputs missing because we already have the tx?
            for (size_t out = 0; out < tx.GetNumVOuts(); out++) {
                // Optimistically just do efficient check of cache for outputs
                if (coins_cache.HaveCoinInCache(COutPoint(hash, out))) {
                    return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-known");
                }
            }
            // Otherwise assume this might be an orphan tx for which we just haven't seen parents yet
            return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
        }
    }

    if (state.m_has_anon_input
         && (::ChainActive().Height() < GetNumBlocksOfPeers()-1)) {
        LogPrintf("%s: Ignoring anon transaction while chain syncs height %d - peers %d.\n",
            __func__, ::ChainActive().Height(), GetNumBlocksOfPeers());
        return false;
    }

    if (!AllAnonOutputsUnknown(tx, state)) { // Also sets state.m_has_anon_output
        // Already in the blockchain, containing block could have been received before loose tx
        return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-in-mempool");
    }
    // Bring the best block into scope
    m_view.GetBestBlock();

    // we have all inputs cached now, so switch back to dummy (to protect
    // against bugs where we pull more inputs from disk that miss being added
    // to coins_to_uncache)
    m_view.SetBackend(m_dummy);

    // Only accept BIP68 sequence locked transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    // Must keep pool.cs for this unless we change CheckSequenceLocks to take a
    // CoinsViewCache instead of create its own
    if (!args.m_test_accept || !args.m_ignore_locks)
    if (!CheckSequenceLocks(m_pool, tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-BIP68-final");

    CAmount nFees = 0;
    if (!Consensus::CheckTxInputs(tx, state, m_view, GetSpendHeight(m_view), nFees)) {
        return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), state.ToString());
    }

    // Check for non-standard pay-to-script-hash in inputs
    if (fRequireStandard && !AreInputsStandard(tx, m_view, nAcceptTime))
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "bad-txns-nonstandard-inputs");

    // Check for non-standard witness in P2WSH
    if (tx.HasWitness() && fRequireStandard && !IsWitnessStandard(tx, m_view))
        return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-witness-nonstandard");

    int64_t nSigOpsCost = GetTransactionSigOpCost(tx, m_view, STANDARD_SCRIPT_VERIFY_FLAGS);

    // nModifiedFees includes any fee deltas from PrioritiseTransaction
    nModifiedFees = nFees;
    m_pool.ApplyDelta(hash, nModifiedFees);

    // Keep track of transactions that spend a coinbase, which we re-scan
    // during reorgs to ensure COINBASE_MATURITY is still met.
    bool fSpendsCoinbase = false;
    for (const CTxIn &txin : tx.vin) {
        if (txin.IsAnonInput()) {
            continue;
        }
        const Coin &coin = m_view.AccessCoin(txin.prevout);
        if (coin.IsCoinBase()) {
            fSpendsCoinbase = true;
            break;
        }
    }

    entry.reset(new CTxMemPoolEntry(ptx, nFees, nAcceptTime, ::ChainActive().Height(),
            fSpendsCoinbase, nSigOpsCost, lp));
    unsigned int nSize = entry->GetTxSize();

    if (nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST)
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "bad-txns-too-many-sigops",
                strprintf("%d", nSigOpsCost));

    // No transactions are allowed below minRelayTxFee except from disconnected
    // blocks
    if (!bypass_limits && !CheckFeeRate(nSize, nModifiedFees, state)) return false;

    if (nAbsurdFee && nFees > nAbsurdFee)
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD,
                "absurdly-high-fee", strprintf("%d > %d", nFees, nAbsurdFee));

    const CTxMemPool::setEntries setIterConflicting = m_pool.GetIterSet(setConflicts);
    // Calculate in-mempool ancestors, up to a limit.
    if (setConflicts.size() == 1) {
        // In general, when we receive an RBF transaction with mempool conflicts, we want to know whether we
        // would meet the chain limits after the conflicts have been removed. However, there isn't a practical
        // way to do this short of calculating the ancestor and descendant sets with an overlay cache of
        // changed mempool entries. Due to both implementation and runtime complexity concerns, this isn't
        // very realistic, thus we only ensure a limited set of transactions are RBF'able despite mempool
        // conflicts here. Importantly, we need to ensure that some transactions which were accepted using
        // the below carve-out are able to be RBF'ed, without impacting the security the carve-out provides
        // for off-chain contract systems (see link in the comment below).
        //
        // Specifically, the subset of RBF transactions which we allow despite chain limits are those which
        // conflict directly with exactly one other transaction (but may evict children of said transaction),
        // and which are not adding any new mempool dependencies. Note that the "no new mempool dependencies"
        // check is accomplished later, so we don't bother doing anything about it here, but if BIP 125 is
        // amended, we may need to move that check to here instead of removing it wholesale.
        //
        // Such transactions are clearly not merging any existing packages, so we are only concerned with
        // ensuring that (a) no package is growing past the package size (not count) limits and (b) we are
        // not allowing something to effectively use the (below) carve-out spot when it shouldn't be allowed
        // to.
        //
        // To check these we first check if we meet the RBF criteria, above, and increment the descendant
        // limits by the direct conflict and its descendants (as these are recalculated in
        // CalculateMempoolAncestors by assuming the new transaction being added is a new descendant, with no
        // removals, of each parent's existing dependent set). The ancestor count limits are unmodified (as
        // the ancestor limits should be the same for both our new transaction and any conflicts).
        // We don't bother incrementing m_limit_descendants by the full removal count as that limit never comes
        // into force here (as we're only adding a single transaction).
        assert(setIterConflicting.size() == 1);
        CTxMemPool::txiter conflict = *setIterConflicting.begin();

        m_limit_descendants += 1;
        m_limit_descendant_size += conflict->GetSizeWithDescendants();
    }

    std::string errString;
    if (!m_pool.CalculateMemPoolAncestors(*entry, setAncestors, m_limit_ancestors, m_limit_ancestor_size, m_limit_descendants, m_limit_descendant_size, errString)) {
        setAncestors.clear();
        // If CalculateMemPoolAncestors fails second time, we want the original error string.
        std::string dummy_err_string;
        // Contracting/payment channels CPFP carve-out:
        // If the new transaction is relatively small (up to 40k weight)
        // and has at most one ancestor (ie ancestor limit of 2, including
        // the new transaction), allow it if its parent has exactly the
        // descendant limit descendants.
        //
        // This allows protocols which rely on distrusting counterparties
        // being able to broadcast descendants of an unconfirmed transaction
        // to be secure by simply only having two immediately-spendable
        // outputs - one for each counterparty. For more info on the uses for
        // this, see https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-November/016518.html
        if (nSize >  EXTRA_DESCENDANT_TX_SIZE_LIMIT ||
                !m_pool.CalculateMemPoolAncestors(*entry, setAncestors, 2, m_limit_ancestor_size, m_limit_descendants + 1, m_limit_descendant_size + EXTRA_DESCENDANT_TX_SIZE_LIMIT, dummy_err_string)) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "too-long-mempool-chain", errString);
        }
    }

    // A transaction that spends outputs that would be replaced by it is invalid. Now
    // that we have the set of all ancestors we can detect this
    // pathological case by making sure setConflicts and setAncestors don't
    // intersect.
    for (CTxMemPool::txiter ancestorIt : setAncestors)
    {
        const uint256 &hashAncestor = ancestorIt->GetTx().GetHash();
        if (setConflicts.count(hashAncestor))
        {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-spends-conflicting-tx",
                    strprintf("%s spends conflicting transaction %s",
                        hash.ToString(),
                        hashAncestor.ToString()));
        }
    }

    // Check if it's economically rational to mine this transaction rather
    // than the ones it replaces.
    nConflictingFees = 0;
    nConflictingSize = 0;
    uint64_t nConflictingCount = 0;

    // If we don't hold the lock allConflicting might be incomplete; the
    // subsequent RemoveStaged() and addUnchecked() calls don't guarantee
    // mempool consistency for us.
    fReplacementTransaction = setConflicts.size();
    if (fReplacementTransaction)
    {
        CFeeRate newFeeRate(nModifiedFees, nSize);
        std::set<uint256> setConflictsParents;
        const int maxDescendantsToVisit = 100;
        for (const auto& mi : setIterConflicting) {
            // Don't allow the replacement to reduce the feerate of the
            // mempool.
            //
            // We usually don't want to accept replacements with lower
            // feerates than what they replaced as that would lower the
            // feerate of the next block. Requiring that the feerate always
            // be increased is also an easy-to-reason about way to prevent
            // DoS attacks via replacements.
            //
            // We only consider the feerates of transactions being directly
            // replaced, not their indirect descendants. While that does
            // mean high feerate children are ignored when deciding whether
            // or not to replace, we do require the replacement to pay more
            // overall fees too, mitigating most cases.
            CFeeRate oldFeeRate(mi->GetModifiedFee(), mi->GetTxSize());
            if (newFeeRate <= oldFeeRate)
            {
                return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "insufficient fee",
                        strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                            hash.ToString(),
                            newFeeRate.ToString(),
                            oldFeeRate.ToString()));
            }

            for (const CTxIn &txin : mi->GetTx().vin)
            {
                if (txin.IsAnonInput()) {
                    continue;
                }
                setConflictsParents.insert(txin.prevout.hash);
            }

            nConflictingCount += mi->GetCountWithDescendants();
        }
        // This potentially overestimates the number of actual descendants
        // but we just want to be conservative to avoid doing too much
        // work.
        if (nConflictingCount <= maxDescendantsToVisit) {
            // If not too many to replace, then calculate the set of
            // transactions that would have to be evicted
            for (CTxMemPool::txiter it : setIterConflicting) {
                m_pool.CalculateDescendants(it, allConflicting);
            }
            for (CTxMemPool::txiter it : allConflicting) {
                nConflictingFees += it->GetModifiedFee();
                nConflictingSize += it->GetTxSize();
            }
        } else {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "too many potential replacements",
                    strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                        hash.ToString(),
                        nConflictingCount,
                        maxDescendantsToVisit));
        }

        for (unsigned int j = 0; j < tx.vin.size(); j++)
        {
            if (tx.vin[j].IsAnonInput()) {
                continue;
            }
            // We don't want to accept replacements that require low
            // feerate junk to be mined first. Ideally we'd keep track of
            // the ancestor feerates and make the decision based on that,
            // but for now requiring all new inputs to be confirmed works.
            //
            // Note that if you relax this to make RBF a little more useful,
            // this may break the CalculateMempoolAncestors RBF relaxation,
            // above. See the comment above the first CalculateMempoolAncestors
            // call for more info.
            if (!setConflictsParents.count(tx.vin[j].prevout.hash))
            {
                // Rather than check the UTXO set - potentially expensive -
                // it's cheaper to just check if the new input refers to a
                // tx that's in the mempool.
                if (m_pool.exists(tx.vin[j].prevout.hash)) {
                    return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "replacement-adds-unconfirmed",
                            strprintf("replacement %s adds unconfirmed input, idx %d",
                                hash.ToString(), j));
                }
            }
        }

        // The replacement must pay greater fees than the transactions it
        // replaces - if we did the bandwidth used by those conflicting
        // transactions would not be paid for.
        if (nModifiedFees < nConflictingFees)
        {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "insufficient fee",
                    strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                        hash.ToString(), FormatMoney(nModifiedFees), FormatMoney(nConflictingFees)));
        }

        // Finally in addition to paying more fees than the conflicts the
        // new transaction must pay for its own bandwidth.
        CAmount nDeltaFees = nModifiedFees - nConflictingFees;
        if (nDeltaFees < ::incrementalRelayFee.GetFee(nSize))
        {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "insufficient fee",
                    strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                        hash.ToString(),
                        FormatMoney(nDeltaFees),
                        FormatMoney(::incrementalRelayFee.GetFee(nSize))));
        }
    }
    return true;
}

bool MemPoolAccept::PolicyScriptChecks(ATMPArgs& args, Workspace& ws, PrecomputedTransactionData& txdata)
{
    const CTransaction& tx = *ws.m_ptx;

    TxValidationState &state = args.m_state;

    constexpr unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;

    // Check input scripts and signatures.
    // This is done last to help prevent CPU exhaustion denial-of-service attacks.
    if (!CheckInputScripts(tx, state, m_view, scriptVerifyFlags, true, false, txdata)) {
        // SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS, so we
        // need to turn both off, and compare against just turning off CLEANSTACK
        // to see if the failure is specifically due to witness validation.
        TxValidationState state_dummy; // Want reported failures to be from first CheckInputScripts
        if (!tx.HasWitness() && CheckInputScripts(tx, state_dummy, m_view, scriptVerifyFlags & ~(SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK), true, false, txdata) &&
                !CheckInputScripts(tx, state_dummy, m_view, scriptVerifyFlags & ~SCRIPT_VERIFY_CLEANSTACK, true, false, txdata)) {
            // Only the witness is missing, so the transaction itself may be fine.
            state.Invalid(TxValidationResult::TX_WITNESS_MUTATED,
                    state.GetRejectReason(), state.GetDebugMessage());
        }
        return false; // state filled in by CheckInputScripts
    }

    return true;
}

bool MemPoolAccept::ConsensusScriptChecks(ATMPArgs& args, Workspace& ws, PrecomputedTransactionData& txdata)
{
    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;

    TxValidationState &state = args.m_state;
    const CChainParams& chainparams = args.m_chainparams;

    // Check again against the current block tip's script verification
    // flags to cache our script execution flags. This is, of course,
    // useless if the next block has different script flags from the
    // previous one, but because the cache tracks script flags for us it
    // will auto-invalidate and we'll just have a few blocks of extra
    // misses on soft-fork activation.
    //
    // This is also useful in case of bugs in the standard flags that cause
    // transactions to pass as valid when they're actually invalid. For
    // instance the STRICTENC flag was incorrectly allowing certain
    // CHECKSIG NOT scripts to pass, even though they were invalid.
    //
    // There is a similar check in CreateNewBlock() to prevent creating
    // invalid blocks (using TestBlockValidity), however allowing such
    // transactions into the mempool can be exploited as a DoS attack.
    unsigned int currentBlockScriptVerifyFlags = GetBlockScriptFlags(::ChainActive().Tip(), chainparams.GetConsensus());
    if (!CheckInputsFromMempoolAndCache(tx, state, m_view, m_pool, currentBlockScriptVerifyFlags, txdata)) {
        return error("%s: BUG! PLEASE REPORT THIS! CheckInputScripts failed against latest-block but not STANDARD flags %s, %s",
                __func__, hash.ToString(), state.ToString());
    }

    return true;
}

bool MemPoolAccept::Finalize(ATMPArgs& args, Workspace& ws)
{
    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;
    TxValidationState &state = args.m_state;
    const bool bypass_limits = args.m_bypass_limits;

    CTxMemPool::setEntries& allConflicting = ws.m_all_conflicting;
    CTxMemPool::setEntries& setAncestors = ws.m_ancestors;
    const CAmount& nModifiedFees = ws.m_modified_fees;
    const CAmount& nConflictingFees = ws.m_conflicting_fees;
    const size_t& nConflictingSize = ws.m_conflicting_size;
    const bool fReplacementTransaction = ws.m_replacement_transaction;
    std::unique_ptr<CTxMemPoolEntry>& entry = ws.m_entry;

    // Remove conflicting transactions from the mempool
    for (CTxMemPool::txiter it : allConflicting)
    {
        LogPrint(BCLog::MEMPOOL, "replacing tx %s with %s for %s additional fees, %d delta bytes\n",
                it->GetTx().GetHash().ToString(),
                hash.ToString(),
                FormatMoney(nModifiedFees - nConflictingFees),
                (int)entry->GetTxSize() - (int)nConflictingSize);
        if (args.m_replaced_transactions)
            args.m_replaced_transactions->push_back(it->GetSharedTx());
    }
    m_pool.RemoveStaged(allConflicting, false, MemPoolRemovalReason::REPLACED);

    // This transaction should only count for fee estimation if:
    // - it isn't a BIP 125 replacement transaction (may not be widely supported)
    // - it's not being re-added during a reorg which bypasses typical mempool fee limits
    // - the node is not behind
    // - the transaction is not dependent on any other transactions in the mempool
    bool validForFeeEstimation = !fReplacementTransaction && !bypass_limits && IsCurrentForFeeEstimation() && m_pool.HasNoInputsOf(tx);

    // Store transaction in memory
    m_pool.addUnchecked(*entry, setAncestors, validForFeeEstimation);

    // trim mempool and check if tx was trimmed
    if (!bypass_limits) {
        LimitMempoolSize(m_pool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, std::chrono::hours{gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY)});
        if (!m_pool.exists(hash))
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "mempool full");
    }

    if (!AddKeyImagesToMempool(tx, m_pool)) {
        LogPrintf("ERROR: %s: AddKeyImagesToMempool failed.\n", __func__);
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-anonin-keyimages");
    }

    // Update mempool indices
    if (fAddressIndex) {
        m_pool.addAddressIndex(*entry, m_view);
    }
    if (fSpentIndex) {
        m_pool.addSpentIndex(*entry, m_view);
    }

    return true;
}

bool MemPoolAccept::AcceptSingleTransaction(const CTransactionRef& ptx, ATMPArgs& args)
{
    AssertLockHeld(cs_main);
    LOCK(m_pool.cs); // mempool "read lock" (held through GetMainSignals().TransactionAddedToMempool())

    Workspace workspace(ptx);

    if (!PreChecks(args, workspace)) return false;

    // Only compute the precomputed transaction data if we need to verify
    // scripts (ie, other policy checks pass). We perform the inexpensive
    // checks first and avoid hashing and signature verification unless those
    // checks pass, to mitigate CPU exhaustion denial-of-service attacks.
    PrecomputedTransactionData txdata;

    if (!PolicyScriptChecks(args, workspace, txdata)) return false;

    if (!ConsensusScriptChecks(args, workspace, txdata)) return false;

    // Tx was accepted, but not added
    if (args.m_test_accept) return true;

    if (!Finalize(args, workspace)) return false;

    GetMainSignals().TransactionAddedToMempool(ptx);

    return true;
}

} // anon namespace

/** (try to) add transaction to memory pool with a specified acceptance time **/
static bool AcceptToMemoryPoolWithTime(const CChainParams& chainparams, CTxMemPool& pool, TxValidationState &state, const CTransactionRef &tx,
                        int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee, bool test_accept, bool ignore_locks) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    std::vector<COutPoint> coins_to_uncache;
    MemPoolAccept::ATMPArgs args { chainparams, state, nAcceptTime, plTxnReplaced, bypass_limits, nAbsurdFee, coins_to_uncache, test_accept, ignore_locks };
    bool res = MemPoolAccept(pool).AcceptSingleTransaction(tx, args);
    if (!res) {
        // Remove coins that were not present in the coins cache before calling ATMPW;
        // this is to prevent memory DoS in case we receive a large number of
        // invalid transactions that attempt to overrun the in-memory coins cache
        // (`CCoinsViewCache::cacheCoins`).

        for (const COutPoint& hashTx : coins_to_uncache)
            ::ChainstateActive().CoinsTip().Uncache(hashTx);
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    BlockValidationState state_dummy;
    ::ChainstateActive().FlushStateToDisk(chainparams, state_dummy, FlushStateMode::PERIODIC);
    return res;
}

bool AcceptToMemoryPool(CTxMemPool& pool, TxValidationState &state, const CTransactionRef &tx,
                        std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee, bool test_accept, bool ignore_locks)
{
    const CChainParams& chainparams = Params();
    return AcceptToMemoryPoolWithTime(chainparams, pool, state, tx, GetTime(), plTxnReplaced, bypass_limits, nAbsurdFee, test_accept, ignore_locks);
}

/**
 * Return transaction in txOut, and if it was found inside a block, its hash is placed in hashBlock.
 * If blockIndex is provided, the transaction is fetched from the corresponding block.
 */
bool GetTransaction(const uint256& hash, CTransactionRef& txOut, const Consensus::Params& consensusParams, uint256& hashBlock, const CBlockIndex* const block_index)
{
    LOCK(cs_main);

    if (!block_index) {
        CTransactionRef ptx = mempool.get(hash);
        if (ptx) {
            txOut = ptx;
            return true;
        }

        if (g_txindex) {
            return g_txindex->FindTx(hash, hashBlock, txOut);
        }
    } else {
        CBlock block;
        if (ReadBlockFromDisk(block, block_index, consensusParams)) {
            for (const auto& tx : block.vtx) {
                if (tx->GetHash() == hash) {
                    txOut = tx;
                    hashBlock = block_index->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}


/** Retrieve a transaction and block header from disk
  * If blockIndex is provided, the transaction is fetched from the corresponding block.
  */
bool GetTransaction(const uint256 &hash, CTransactionRef &txOut, const Consensus::Params &consensusParams, CBlock &block, bool fAllowSlow, CBlockIndex* blockIndex)
{
    CBlockIndex *pindexSlow = blockIndex;

    LOCK(cs_main);

    if (g_txindex) {
        CBlockHeader header;
        if (g_txindex->FindTx(hash, header, txOut)) {
            block = CBlock(header);
            return true;
        }
        return false;
    }

    if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
        const Coin& coin = AccessByTxid(::ChainstateActive().CoinsTip(), hash);
        if (!coin.IsSpent()) pindexSlow = ::ChainActive()[coin.nHeight];
    }

    if (pindexSlow) {
        // read and return entire block
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) {
            for (const auto& tx : block.vtx) {
                if (tx->GetHash() == hash) {
                    txOut = tx;
                    return true;
                }
            }
        }
    }

    return false;
}


//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static bool WriteBlockToDisk(const CBlock& block, FlatFilePos& pos, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk: OpenBlockFile failed");

    // Write index header
    unsigned int nSize = GetSerializeSize(block, fileout.GetVersion());
    fileout << messageStart << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const FlatFilePos& pos, const Consensus::Params& consensusParams)
{
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    // Read block
    try {
        filein >> block;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Check the header
    if (fGhostMode) {
        // only CheckProofOfWork for genesis blocks
        if (block.hashPrevBlock.IsNull()
            && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams, 0, Params().GetLastImportHeight())) {
            return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());
        }
    } else {
        if (!CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
            return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());
    }

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    FlatFilePos blockPos;
    {
        LOCK(cs_main);
        blockPos = pindex->GetBlockPos();
    }

    if (!ReadBlockFromDisk(block, blockPos, consensusParams))
        return false;
    if (block.GetHash() != pindex->GetBlockHash())
        return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s",
                pindex->ToString(), pindex->GetBlockPos().ToString());
    return true;
}

bool ReadTransactionFromDiskBlock(const CBlockIndex* pindex, int nIndex, CTransactionRef &txOut)
{
    FlatFilePos hpos;
    {
        LOCK(cs_main);
        hpos = pindex->GetBlockPos();
    }

    // Open history file to read
    CAutoFile filein(OpenBlockFile(hpos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenBlockFile failed for %s", __func__, hpos.ToString());

    CBlockHeader blockHeader;
    try {
        filein >> blockHeader;

        int nTxns = ReadCompactSize(filein);

        if (nTxns <= nIndex || nIndex < 0)
            return error("%s: Block %s, txn %d not in available range %d.", __func__, pindex->GetBlockPos().ToString(), nIndex, nTxns);

        for (int k = 0; k <= nIndex; ++k)
            filein >> txOut;
    } catch (const std::exception& e)
    {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), hpos.ToString());
    }

    if (blockHeader.GetHash() != pindex->GetBlockHash())
        return error("%s: Hash doesn't match index for %s at %s",
                __func__, pindex->ToString(), hpos.ToString());
    return true;
}

bool ReadRawBlockFromDisk(std::vector<uint8_t>& block, const FlatFilePos& pos, const CMessageHeader::MessageStartChars& message_start)
{
    FlatFilePos hpos = pos;
    hpos.nPos -= 8; // Seek back 8 bytes for meta header
    CAutoFile filein(OpenBlockFile(hpos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        return error("%s: OpenBlockFile failed for %s", __func__, pos.ToString());
    }

    try {
        CMessageHeader::MessageStartChars blk_start;
        unsigned int blk_size;

        filein >> blk_start >> blk_size;

        if (memcmp(blk_start, message_start, CMessageHeader::MESSAGE_START_SIZE)) {
            return error("%s: Block magic mismatch for %s: %s versus expected %s", __func__, pos.ToString(),
                    HexStr(blk_start, blk_start + CMessageHeader::MESSAGE_START_SIZE),
                    HexStr(message_start, message_start + CMessageHeader::MESSAGE_START_SIZE));
        }

        if (blk_size > MAX_SIZE) {
            return error("%s: Block data is larger than maximum deserialization size for %s: %s versus %s", __func__, pos.ToString(),
                    blk_size, MAX_SIZE);
        }

        block.resize(blk_size); // Zeroing of memory is intentional here
        filein.read((char*)block.data(), blk_size);
    } catch(const std::exception& e) {
        return error("%s: Read from block file failed: %s for %s", __func__, e.what(), pos.ToString());
    }

    return true;
}

bool ReadRawBlockFromDisk(std::vector<uint8_t>& block, const CBlockIndex* pindex, const CMessageHeader::MessageStartChars& message_start)
{
    FlatFilePos block_pos;
    {
        LOCK(cs_main);
        block_pos = pindex->GetBlockPos();
    }

    return ReadRawBlockFromDisk(block, block_pos, message_start);
}

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    CAmount nSubsidy = 50 * COIN;
    // Subsidy is cut in half every 210,000 blocks which will occur approximately every 4 years.
    nSubsidy >>= halvings;
    return nSubsidy;
}

//! Returns last CBlockIndex* that is a checkpoint
static CBlockIndex* GetLastCheckpoint(const CCheckpointData& data) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const MapCheckpoints& checkpoints = data.mapCheckpoints;

    for (const MapCheckpoints::value_type& i : reverse_iterate(checkpoints))
    {
        const uint256& hash = i.second;
        CBlockIndex* pindex = LookupBlockIndex(hash);
        if (pindex) {
            return pindex;
        }
    }
    return nullptr;
}


class HeightEntry {
public:
    HeightEntry(int height, NodeId id, int64_t time) : m_height(height), m_id(id), m_time(time)  {};
    int m_height;
    NodeId m_id;
    int64_t m_time;
};
static std::atomic_int nPeerBlocks(std::numeric_limits<int>::max());
static std::atomic_int nPeers(0);
static std::list<HeightEntry> peer_blocks;
const size_t max_peer_blocks = 9;

void UpdateNumPeers(int num_peers)
{
    nPeers = num_peers;
}

int GetNumPeers()
{
    return nPeers;
}

void UpdateNumBlocksOfPeers(NodeId id, int height) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    // Select median value. Only one sample per peer. Remove oldest sample.
    int new_value = 0;

    bool inserted = false;
    size_t num_elements = 0;
    std::list<HeightEntry>::iterator oldest = peer_blocks.end();
    for (auto it = peer_blocks.begin(); it != peer_blocks.end(); ) {
        if (id == it->m_id) {
            if (height == it->m_height) {
                inserted = true;
            } else {
                it = peer_blocks.erase(it);
                continue;
            }
        }
        if (!inserted && it->m_height > height) {
            peer_blocks.emplace(it, height, id, GetTime());
            inserted = true;
        }
        if (oldest == peer_blocks.end() || oldest->m_time > it->m_time) {
            oldest = it;
        }
        it++;
        num_elements++;
    }

    if (!inserted) {
        peer_blocks.emplace_back(height, id, GetTime());
        num_elements++;
    }
    if (num_elements > max_peer_blocks && oldest != peer_blocks.end()) {
        peer_blocks.erase(oldest);
        num_elements--;
    }

    size_t stop = num_elements / 2;
    num_elements = 0;
    for (auto it = peer_blocks.begin(); it != peer_blocks.end(); ++it) {
        if (num_elements >= stop) {
            new_value = it->m_height;
            break;
        }
        num_elements++;
    }

    static const CBlockIndex *pcheckpoint = GetLastCheckpoint(Params().Checkpoints());
    if (pcheckpoint) {
        if (new_value < pcheckpoint->nHeight) {
            new_value = std::numeric_limits<int>::max();
        }
    }
    nPeerBlocks = new_value;
}

int GetNumBlocksOfPeers()
{
    return nPeerBlocks;
}

CoinsViews::CoinsViews(
    std::string ldb_name,
    size_t cache_size_bytes,
    bool in_memory,
    bool should_wipe) : m_dbview(
                            GetDataDir() / ldb_name, cache_size_bytes, in_memory, should_wipe),
                        m_catcherview(&m_dbview) {}

void CoinsViews::InitCache()
{
    m_cacheview = MakeUnique<CCoinsViewCache>(&m_catcherview);
}

CChainState::CChainState(BlockManager& blockman, uint256 from_snapshot_blockhash)
    : m_blockman(blockman),
      m_from_snapshot_blockhash(from_snapshot_blockhash) {}

void CChainState::InitCoinsDB(
    size_t cache_size_bytes,
    bool in_memory,
    bool should_wipe,
    std::string leveldb_name)
{
    if (!m_from_snapshot_blockhash.IsNull()) {
        leveldb_name += "_" + m_from_snapshot_blockhash.ToString();
    }

    m_coins_views = MakeUnique<CoinsViews>(
        leveldb_name, cache_size_bytes, in_memory, should_wipe);
}

void CChainState::InitCoinsCache()
{
    assert(m_coins_views != nullptr);
    m_coins_views->InitCache();
}

// Note that though this is marked const, we may end up modifying `m_cached_finished_ibd`, which
// is a performance-related implementation detail. This function must be marked
// `const` so that `CValidationInterface` clients (which are given a `const CChainState*`)
// can call it.
//
bool CChainState::IsInitialBlockDownload() const
{
    // Optimization: pre-test latch before taking the lock.
    if (m_cached_finished_ibd.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (m_cached_finished_ibd.load(std::memory_order_relaxed))
        return false;
    if (fImporting || fReindex)
        return true;
    if (m_chain.Tip() == nullptr)
        return true;
    if (m_chain.Tip()->nChainWork < nMinimumChainWork)
        return true;
    if (m_chain.Tip()->nHeight > COINBASE_MATURITY
        && m_chain.Tip()->GetBlockTime() < (GetTime() - nMaxTipAge))
        return true;
    if (fGhostMode
        && (GetNumPeers() < 1
            || m_chain.Tip()->nHeight < GetNumBlocksOfPeers()-10))
        return true;

    LogPrintf("Leaving InitialBlockDownload (latching to false)\n");
    m_cached_finished_ibd.store(true, std::memory_order_relaxed);
    return false;
}

static CBlockIndex *pindexBestForkTip = nullptr, *pindexBestForkBase = nullptr;

BlockMap& BlockIndex()
{
    LOCK(::cs_main);
    return g_chainman.m_blockman.m_block_index;
}

static void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
#if HAVE_SYSTEM
    std::string strCmd = gArgs.GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    std::thread t(runCommand, strCmd);
    t.detach(); // thread runs free
#endif
}

static void CheckForkWarningConditions() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial sync)
    if (::ChainstateActive().IsInitialBlockDownload())
        return;

    // If our best fork is no longer within 72 blocks (+/- 12 hours if no one mines it)
    // of our head, drop it
    if (pindexBestForkTip && ::ChainActive().Height() - pindexBestForkTip->nHeight >= 72)
        pindexBestForkTip = nullptr;

    if (pindexBestForkTip || (pindexBestInvalid && pindexBestInvalid->nChainWork > ::ChainActive().Tip()->nChainWork + (GetBlockProof(*::ChainActive().Tip()) * 6)))
    {
        if (!GetfLargeWorkForkFound() && pindexBestForkBase)
        {
            std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                pindexBestForkBase->phashBlock->ToString() + std::string("'");
            AlertNotify(warning);
        }
        if (pindexBestForkTip && pindexBestForkBase)
        {
            LogPrintf("%s: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n", __func__,
                   pindexBestForkBase->nHeight, pindexBestForkBase->phashBlock->ToString(),
                   pindexBestForkTip->nHeight, pindexBestForkTip->phashBlock->ToString());
            SetfLargeWorkForkFound(true);
        }
        else
        {
            LogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n", __func__);
            SetfLargeWorkInvalidChainFound(true);
        }
    }
    else
    {
        SetfLargeWorkForkFound(false);
        SetfLargeWorkInvalidChainFound(false);
    }
}

static void CheckForkWarningConditionsOnNewFork(CBlockIndex* pindexNewForkTip) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    CBlockIndex* pfork = pindexNewForkTip;
    CBlockIndex* plonger = ::ChainActive().Tip();
    while (pfork && pfork != plonger)
    {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 blocks
    // with a tip within 72 blocks (+/- 12 hours if no one mines it) of ours
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!pindexBestForkTip || pindexNewForkTip->nHeight > pindexBestForkTip->nHeight) &&
            pindexNewForkTip->nChainWork - pfork->nChainWork > (GetBlockProof(*pfork) * 7) &&
            ::ChainActive().Height() - pindexNewForkTip->nHeight < 72)
    {
        pindexBestForkTip = pindexNewForkTip;
        pindexBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

// Called both upon regular invalid block discovery *and* InvalidateBlock
void static InvalidChainFound(CBlockIndex* pindexNew) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!pindexBestInvalid || pindexNew->nChainWork > pindexBestInvalid->nChainWork)
        pindexBestInvalid = pindexNew;
    if (pindexBestHeader != nullptr && pindexBestHeader->GetAncestor(pindexNew->nHeight) == pindexNew) {
        pindexBestHeader = ::ChainActive().Tip();
    }

    LogPrintf("%s: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
      log(pindexNew->nChainWork.getdouble())/log(2.0), FormatISO8601DateTime(pindexNew->GetBlockTime()));
    CBlockIndex *tip = ::ChainActive().Tip();
    assert (tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      tip->GetBlockHash().ToString(), ::ChainActive().Height(), log(tip->nChainWork.getdouble())/log(2.0),
      FormatISO8601DateTime(tip->GetBlockTime()));
    CheckForkWarningConditions();
}

// Same as InvalidChainFound, above, except not called directly from InvalidateBlock,
// which does its own setBlockIndexCandidates manageent.
void CChainState::InvalidBlockFound(CBlockIndex *pindex, const CBlock &block, const BlockValidationState &state) {
    if (state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        m_blockman.m_failed_blocks.insert(pindex);
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());
        for (const CTxIn &txin : tx.vin)
        {
            if (txin.IsAnonInput()) {
                continue;
            }

            txundo.vprevout.emplace_back();
            bool is_spent = inputs.SpendCoin(txin.prevout, &txundo.vprevout.back());
            assert(is_spent);
        }
    }
    // add outputs
    AddCoins(inputs, tx, nHeight);
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight)
{
    CTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight);
}

bool CScriptCheck::operator()() {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness *witness = &ptxTo->vin[nIn].scriptWitness;

    return VerifyScript(scriptSig, scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, vchAmount, cacheStore, *txdata), &error);
    //return VerifyScript(scriptSig, m_tx_out.scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, m_tx_out.nValue, cacheStore, *txdata), &error);
}

int GetSpendHeight(const CCoinsViewCache& inputs)
{
    LOCK(cs_main);

    const CBlockIndex* pindexPrev = LookupBlockIndex(inputs.GetBestBlock());

    if (!pindexPrev)
        return 0;

    return pindexPrev->nHeight + 1;
}

static CuckooCache::cache<uint256, SignatureCacheHasher> scriptExecutionCache;
static uint256 scriptExecutionCacheNonce(GetRandHash());

void InitScriptExecutionCache() {
    // nMaxCacheSize is unsigned. If -maxsigcachesize is set to zero,
    // setup_bytes creates the minimum possible cache (2 elements).
    size_t nMaxCacheSize = std::min(std::max((int64_t)0, gArgs.GetArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE) / 2), MAX_MAX_SIG_CACHE_SIZE) * ((size_t) 1 << 20);
    size_t nElems = scriptExecutionCache.setup_bytes(nMaxCacheSize);
    LogPrintf("Using %zu MiB out of %zu/2 requested for script execution cache, able to store %zu elements\n",
            (nElems*sizeof(uint256)) >>20, (nMaxCacheSize*2)>>20, nElems);
}

/**
 * Check whether all of this transaction's input scripts succeed.
 *
 * This involves ECDSA signature checks so can be computationally intensive. This function should
 * only be called after the cheap sanity checks in CheckTxInputs passed.
 *
 * If pvChecks is not nullptr, script checks are pushed onto it instead of being performed inline. Any
 * script checks which are not necessary (eg due to script execution cache hits) are, obviously,
 * not pushed onto pvChecks/run.
 *
 * Setting cacheSigStore/cacheFullScriptStore to false will remove elements from the corresponding cache
 * which are matched. This is useful for checking blocks where we will likely never need the cache
 * entry again.
 *
 * Note that we may set state.reason to NOT_STANDARD for extra soft-fork flags in flags, block-checking
 * callers should probably reset it to CONSENSUS in such cases.
 *
 * Non-static (and re-declared) in src/test/txvalidationcache_tests.cpp
 */
bool CheckInputScripts(const CTransaction& tx, TxValidationState &state, const CCoinsViewCache &inputs, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks, bool fAnonChecks) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (tx.IsCoinBase()) return true;
    if (pvChecks) {
        pvChecks->reserve(tx.vin.size());
    }

    bool m_has_anon_input = false;
    // First check if script executions have been cached with the same
    // flags. Note that this assumes that the inputs provided are
    // correct (ie that the transaction hash which is in tx's prevouts
    // properly commits to the scriptPubKey in the inputs view of that
    // transaction).
    uint256 hashCacheEntry;
    // We only use the first 19 bytes of nonce to avoid a second SHA
    // round - giving us 19 + 32 + 4 = 55 bytes (+ 8 + 1 = 64)
    static_assert(55 - sizeof(flags) - 32 >= 128/8, "Want at least 128 bits of nonce for script execution cache");
    CSHA256().Write(scriptExecutionCacheNonce.begin(), 55 - sizeof(flags) - 32).Write(tx.GetWitnessHash().begin(), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(hashCacheEntry.begin());
    AssertLockHeld(cs_main); //TODO: Remove this requirement by making CuckooCache not require external locks

    if (scriptExecutionCache.contains(hashCacheEntry, !cacheFullScriptStore)) {
        return true;
    }

    if (!txdata.m_ready) {
        txdata.Init(tx);
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        if (tx.vin[i].IsAnonInput()) {
            m_has_anon_input = true;
            continue;
        }

        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // We very carefully only pass in things to CScriptCheck which
        // are clearly committed to by tx' witness hash. This provides
        // a sanity check that our caching is not introducing consensus
        // failures through additional data in, eg, the coins being
        // spent being checked as a part of CScriptCheck.
        const CScript& scriptPubKey = coin.out.scriptPubKey;
        const CAmount amount = coin.out.nValue;

        std::vector<uint8_t> vchAmount;
        if (coin.nType == OUTPUT_STANDARD) {
            vchAmount.resize(8);
            memcpy(vchAmount.data(), &amount, sizeof(amount));
        } else
        if (coin.nType == OUTPUT_CT) {
            vchAmount.resize(33);
            memcpy(vchAmount.data(), coin.commitment.data, 33);
        }

        // Verify signature
        CScriptCheck check(scriptPubKey, vchAmount, tx, i, flags, cacheSigStore, &txdata);
        if (pvChecks) {
            pvChecks->push_back(CScriptCheck());
            check.swap(pvChecks->back());
        } else if (!check()) {
            if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                // Check whether the failure was caused by a
                // non-mandatory script verification check, such as
                // non-standard DER encodings or non-null dummy
                // arguments; if so, ensure we return NOT_STANDARD
                // instead of CONSENSUS to avoid downstream users
                // splitting the network between upgraded and
                // non-upgraded nodes by banning CONSENSUS-failing
                // data providers.
                CScriptCheck check2(scriptPubKey, vchAmount, tx, i,
                        flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheSigStore, &txdata);

                if (check2())
                    return state.Invalid(TxValidationResult::TX_NOT_STANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
            }
            // MANDATORY flag failures correspond to
            // TxValidationResult::TX_CONSENSUS. Because CONSENSUS
            // failures are the most serious case of validation
            // failures, we may need to consider using
            // RECENT_CONSENSUS_CHANGE for any script failure that
            // could be due to non-upgraded nodes which we may want to
            // support, to avoid splitting the network (but this
            // depends on the details of how net_processing handles
            // such errors).
            return state.Invalid(TxValidationResult::TX_CONSENSUS, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
        }
    }

    if (m_has_anon_input && fAnonChecks
        && !VerifyMLSAG(tx, state)) {
        return false;
    }

    if (cacheFullScriptStore && !pvChecks) {
        // We executed all of the provided scripts, and were told to
        // cache the result. Do so now.
        scriptExecutionCache.insert(hashCacheEntry);
    }

    return true;
}

static bool UndoWriteToDisk(const CBlockUndo& blockundo, FlatFilePos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = GetSerializeSize(blockundo, fileout.GetVersion());
    fileout << messageStart << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

bool UndoReadFromDisk(CBlockUndo& blockundo, const CBlockIndex* pindex)
{
    FlatFilePos pos = pindex->GetUndoPos();
    if (pos.IsNull()) {
        return error("%s: no undo data available", __func__);
    }

    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Read block
    uint256 hashChecksum, nullHash;
    CHashVerifier<CAutoFile> verifier(&filein); // We need a CHashVerifier as reserializing may lose data
    try {
        verifier << (pindex->pprev ? pindex->pprev->GetBlockHash() : nullHash);
        verifier >> blockundo;
        filein >> hashChecksum;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.GetHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

/** Abort with a message */
static bool AbortNode(const std::string& strMessage, const std::string& userMessage = "", unsigned int prefix = 0)
{
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    if (!userMessage.empty()) {
        uiInterface.ThreadSafeMessageBox(userMessage, "", CClientUIInterface::MSG_ERROR | prefix);
    } else {
        uiInterface.ThreadSafeMessageBox(_("Error: A fatal internal error occurred, see debug.log for details").translated, "", CClientUIInterface::MSG_ERROR | CClientUIInterface::MSG_NOPREFIX);
    }
    StartShutdown();
    return false;
}

static bool AbortNode(BlockValidationState& state, const std::string& strMessage, const std::string& userMessage = "", unsigned int prefix = 0)
{
    AbortNode(strMessage, userMessage, prefix);
    return state.Error(strMessage);
}

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */
int ApplyTxInUndo(Coin&& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output

    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    // If the coin already exists as an unspent coin in the cache, then the
    // possible_overwrite parameter to AddCoin must be set to true. We have
    // already checked whether an unspent coin exists above using HaveCoin, so
    // we don't need to guess. When fClean is false, an unspent coin already
    // existed and it is an overwrite.
    view.AddCoin(out, std::move(undo), !fClean);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When FAILED is returned, view is left in an indeterminate state. */
DisconnectResult CChainState::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view)
{
    if (LogAcceptCategory(BCLog::HDWALLET))
        LogPrintf("%s: hash %s, height %d\n", __func__, block.GetHash().ToString(), pindex->nHeight);

    assert(pindex->GetBlockHash() == view.GetBestBlock());

    bool fClean = true;

    CBlockUndo blockUndo;
    if (!UndoReadFromDisk(blockUndo, pindex)) {
        error("DisconnectBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }

    if (!fGhostMode) {
        if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
            error("DisconnectBlock(): block and undo data inconsistent");
            return DISCONNECT_FAILED;
        }
    } else {
        if (blockUndo.vtxundo.size() != block.vtx.size()) {
            // Count non coinbase txns, this should only happen in early blocks.
            size_t nExpectTxns = 0;
            for (auto &tx : block.vtx) {
                if (!tx->IsCoinBase()) {
                    nExpectTxns++;
                }
            }

            if (blockUndo.vtxundo.size() != nExpectTxns) {
                error("DisconnectBlock(): block and undo data inconsistent");
                return DISCONNECT_FAILED;
            }
        }
    }

    int nVtxundo = (int)blockUndo.vtxundo.size()-1;
    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--)
    {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();

        for (const auto &txin : tx.vin) {
            if (txin.IsAnonInput()) {
                uint32_t nInputs, nRingSize;
                txin.GetAnonInfo(nInputs, nRingSize);
                if (txin.scriptData.stack.size() != 1
                    || txin.scriptData.stack[0].size() != 33 * nInputs) {
                    error("%s: Bad scriptData stack, %s.", __func__, hash.ToString());
                    return DISCONNECT_FAILED;
                }

                const std::vector<uint8_t> &vKeyImages = txin.scriptData.stack[0];
                for (size_t k = 0; k < nInputs; ++k) {
                    const CCmpPubKey &ki = *((CCmpPubKey*)&vKeyImages[k*33]);

                    view.keyImages.push_back(std::make_pair(ki, hash));
                }
            } else {
                Coin coin;
                view.spent_cache.emplace_back(txin.prevout, SpentCoin());
            }
        }

        bool is_coinbase = tx.IsCoinBase() || tx.IsCoinStake();

        for (size_t k = tx.vpout.size(); k-- > 0;) {
            const CTxOutBase *out = tx.vpout[k].get();

            if (out->IsType(OUTPUT_RINGCT)) {
                CTxOutRingCT *txout = (CTxOutRingCT*)out;

                if (view.nLastRCTOutput == 0) {
                    view.nLastRCTOutput = pindex->nAnonOutputs;
                    // Verify data matches
                    CAnonOutput ao;
                    if (!pblocktree->ReadRCTOutput(view.nLastRCTOutput, ao)) {
                        error("%s: RCT output missing, txn %s, %d, index %d.", __func__, hash.ToString(), k, view.nLastRCTOutput);
                        if (!view.fForceDisconnect) {
                            return DISCONNECT_FAILED;
                        }
                    } else
                    if (ao.pubkey != txout->pk) {
                        error("%s: RCT output mismatch, txn %s, %d, index %d.", __func__, hash.ToString(), k, view.nLastRCTOutput);
                        if (!view.fForceDisconnect) {
                            return DISCONNECT_FAILED;
                        }
                    }
                }

                view.anonOutputLinks[txout->pk] = view.nLastRCTOutput;
                view.nLastRCTOutput--;

                continue;
            }

            // Check that all outputs are available and match the outputs in the block itself
            // exactly.
            if (out->IsType(OUTPUT_STANDARD) || out->IsType(OUTPUT_CT)) {
                const CScript *pScript = out->GetPScriptPubKey();
                if (!pScript->IsUnspendable()) {
                    COutPoint op(hash, k);
                    Coin coin;

                    CTxOut txout(0, *pScript);

                    if (out->IsType(OUTPUT_STANDARD)) {
                        txout.nValue = out->GetValue();
                    }
                    bool is_spent = view.SpendCoin(op, &coin);
                    if (!is_spent || txout != coin.out || pindex->nHeight != coin.nHeight || is_coinbase != coin.fCoinBase) {
                        fClean = false; // transaction output mismatch
                    }
                }
            }

            if (!fAddressIndex
                || (!out->IsType(OUTPUT_STANDARD)
                && !out->IsType(OUTPUT_CT))) {
                continue;
            }

            const CScript *pScript;
            std::vector<unsigned char> hashBytes;
            int scriptType = 0;
            CAmount nValue;
            if (!ExtractIndexInfo(out, scriptType, hashBytes, nValue, pScript)
                || scriptType == 0) {
                continue;
            }
            // undo receiving activity
            view.addressIndex.push_back(std::make_pair(CAddressIndexKey(scriptType, uint256(hashBytes.data(), hashBytes.size()), pindex->nHeight, i, hash, k, false), nValue));
            // undo unspent index
            view.addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(scriptType, uint256(hashBytes.data(), hashBytes.size()), hash, k), CAddressUnspentValue()));
        }


        if (fGhostMode) {
            // restore inputs
            if (!tx.IsCoinBase()) {
                if (nVtxundo < 0 || nVtxundo >= (int)blockUndo.vtxundo.size()) {
                    error("DisconnectBlock(): transaction undo data offset out of range.");
                    return DISCONNECT_FAILED;
                }

                size_t nExpectUndo = 0;
                for (const auto &txin : tx.vin)
                if (!txin.IsAnonInput()) {
                    nExpectUndo++;
                }

                CTxUndo &txundo = blockUndo.vtxundo[nVtxundo--];
                if (txundo.vprevout.size() != nExpectUndo) {
                    error("DisconnectBlock(): transaction and undo data inconsistent");
                    return DISCONNECT_FAILED;
                }

                for (unsigned int j = tx.vin.size(); j-- > 0;) {
                    if (tx.vin[j].IsAnonInput()) {
                        continue;
                    }

                    const COutPoint &out = tx.vin[j].prevout;
                    int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                    if (res == DISCONNECT_FAILED) {
                        error("DisconnectBlock(): ApplyTxInUndo failed");
                        return DISCONNECT_FAILED;
                    }
                    fClean = fClean && res != DISCONNECT_UNCLEAN;

                    const CTxIn input = tx.vin[j];

                    if (fSpentIndex) { // undo and delete the spent index
                        view.spentIndex.push_back(std::make_pair(CSpentIndexKey(input.prevout.hash, input.prevout.n), CSpentIndexValue()));
                    }

                    if (fAddressIndex) {
                        const Coin &coin = view.AccessCoin(tx.vin[j].prevout);
                        const CScript *pScript = &coin.out.scriptPubKey;

                        CAmount nValue = coin.nType == OUTPUT_CT ? 0 : coin.out.nValue;
                        std::vector<uint8_t> hashBytes;
                        int scriptType = 0;
                        if (!ExtractIndexInfo(pScript, scriptType, hashBytes)
                            || scriptType == 0) {
                            continue;
                        }

                        // undo spending activity
                        view.addressIndex.push_back(std::make_pair(CAddressIndexKey(scriptType, uint256(hashBytes.data(), hashBytes.size()), pindex->nHeight, i, hash, j, true), nValue * -1));
                        // restore unspent index
                        view.addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(scriptType, uint256(hashBytes.data(), hashBytes.size()), input.prevout.hash, input.prevout.n), CAddressUnspentValue(nValue, *pScript, coin.nHeight)));
                    }
                }
            }
        } else {
            // Check that all outputs are available and match the outputs in the block itself
            // exactly.
            for (size_t o = 0; o < tx.vout.size(); o++) {
                if (!tx.vout[o].scriptPubKey.IsUnspendable()) {
                    COutPoint out(hash, o);
                    Coin coin;
                    bool is_spent = view.SpendCoin(out, &coin);
                    if (!is_spent || tx.vout[o] != coin.out || pindex->nHeight != coin.nHeight || is_coinbase != coin.fCoinBase) {
                        fClean = false; // transaction output mismatch
                    }
                }
            }

            if (i > 0) { // not coinbases
                CTxUndo &txundo = blockUndo.vtxundo[i-1];
                if (txundo.vprevout.size() != tx.vin.size()) {
                    error("DisconnectBlock(): transaction and undo data inconsistent");
                    return DISCONNECT_FAILED;
                }
                for (unsigned int j = tx.vin.size(); j-- > 0;) {
                    const COutPoint &out = tx.vin[j].prevout;
                    int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                    if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
                    fClean = fClean && res != DISCONNECT_UNCLEAN;
                }
            }
            // At this point, all of txundo.vprevout should have been moved out.
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash(), pindex->pprev->nHeight);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

bool ConnectBlock(const CBlock& block, BlockValidationState& state, CBlockIndex* pindex,
    CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck)
{
    return ::ChainstateActive().ConnectBlock(block, state, pindex, view, chainparams, fJustCheck);
};

DisconnectResult DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view)
{
    return ::ChainstateActive().DisconnectBlock(block, pindex, view);
};

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    FlatFilePos block_pos_old(nLastBlockFile, vinfoBlockFile[nLastBlockFile].nSize);
    FlatFilePos undo_pos_old(nLastBlockFile, vinfoBlockFile[nLastBlockFile].nUndoSize);

    bool status = true;
    status &= BlockFileSeq().Flush(block_pos_old, fFinalize);
    status &= UndoFileSeq().Flush(undo_pos_old, fFinalize);
    if (!status) {
        AbortNode("Flushing block file to disk failed. This is likely the result of an I/O error.");
    }
}

static bool FindUndoPos(BlockValidationState &state, int nFile, FlatFilePos &pos, unsigned int nAddSize);

static bool WriteUndoDataForBlock(const CBlockUndo& blockundo, BlockValidationState& state, CBlockIndex* pindex, const CChainParams& chainparams)
{
    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull()) {
        FlatFilePos _pos;
        if (!FindUndoPos(state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, CLIENT_VERSION) + 40))
            return error("ConnectBlock(): FindUndoPos failed");

        uint256 nullHash;
        if (!UndoWriteToDisk(blockundo, _pos, pindex->pprev ? pindex->pprev->GetBlockHash() : nullHash, chainparams.MessageStart()))
            return AbortNode(state, "Failed to write undo data");

        // update nUndoPos in block index
        pindex->nUndoPos = _pos.nPos;
        pindex->nStatus |= BLOCK_HAVE_UNDO;
        setDirtyBlockIndex.insert(pindex);
    }

    return true;
}

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck(int worker_num) {
    util::ThreadRename(strprintf("scriptch.%i", worker_num));
    scriptcheckqueue.Thread();
}

VersionBitsCache versionbitscache GUARDED_BY(cs_main);

int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        ThresholdState state = VersionBitsState(pindexPrev, params, static_cast<Consensus::DeploymentPos>(i), versionbitscache);
        if (state == ThresholdState::LOCKED_IN || state == ThresholdState::STARTED) {
            nVersion |= VersionBitsMask(params, static_cast<Consensus::DeploymentPos>(i));
        }
    }

    return nVersion;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    int bit;

public:
    explicit WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const override { return 0; }
    int64_t EndTime(const Consensus::Params& params) const override { return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const override { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const override { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const override
    {
        return pindex->nHeight >= params.MinBIP9WarningHeight &&
               ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> bit) & 1) != 0 &&
               ((ComputeBlockVersion(pindex->pprev, params) >> bit) & 1) == 0;
    }
};

static ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS] GUARDED_BY(cs_main);

// 0.13.0 was shipped with a segwit deployment defined for testnet, but not for
// mainnet. We no longer need to support disabling the segwit deployment
// except for testing purposes, due to limitations of the functional test
// environment. See test/functional/p2p-segwit.py.
static bool IsScriptWitnessEnabled(const Consensus::Params& params)
{
    return params.SegwitHeight != std::numeric_limits<int>::max();
}

static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& consensusparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);

    if (fGhostMode) {
        unsigned int flags = SCRIPT_VERIFY_P2SH;
        flags |= SCRIPT_VERIFY_DERSIG;
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        flags |= SCRIPT_VERIFY_WITNESS;
        flags |= SCRIPT_VERIFY_NULLDUMMY;
        return flags;
    }

    unsigned int flags = SCRIPT_VERIFY_NONE;

    // BIP16 didn't become active until Apr 1 2012 (on mainnet, and
    // retroactively applied to testnet)
    // However, only one historical block violated the P2SH rules (on both
    // mainnet and testnet), so for simplicity, always leave P2SH
    // on except for the one violating block.
    if (consensusparams.BIP16Exception.IsNull() || // no bip16 exception on this chain
        pindex->phashBlock == nullptr || // this is a new candidate block, eg from TestBlockValidity()
        *pindex->phashBlock != consensusparams.BIP16Exception) // this block isn't the historical exception
    {
        flags |= SCRIPT_VERIFY_P2SH;
    }

    // Enforce WITNESS rules whenever P2SH is in effect (and the segwit
    // deployment is defined).
    if (flags & SCRIPT_VERIFY_P2SH && IsScriptWitnessEnabled(consensusparams)) {
        flags |= SCRIPT_VERIFY_WITNESS;
    }

    // Start enforcing the DERSIG (BIP66) rule
    if (pindex->nHeight >= consensusparams.BIP66Height) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY (BIP65) rule
    if (pindex->nHeight >= consensusparams.BIP65Height) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP112 (CHECKSEQUENCEVERIFY)
    if (pindex->nHeight >= consensusparams.CSVHeight) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }

    // Start enforcing BIP147 NULLDUMMY (activated simultaneously with segwit)
    if (IsWitnessEnabled(pindex->pprev, consensusparams)) {
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    return flags;
}



static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
static int64_t nTimeTotal = 0;
static int64_t nBlocksTotal = 0;

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
bool CChainState::ConnectBlock(const CBlock& block, BlockValidationState& state, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck)
{
    AssertLockHeld(cs_main);
    assert(pindex);
    assert(*pindex->phashBlock == block.GetHash());
    int64_t nTimeStart = GetTimeMicros();

    const Consensus::Params &consensus = Params().GetConsensus();
    state.SetStateInfo(block.nTime, pindex->nHeight, consensus, fGhostMode, (fBusyImporting && fSkipRangeproof));

    // Check it again in case a previous version let a bad block in
    // NOTE: We don't currently (re-)invoke ContextualCheckBlock() or
    // ContextualCheckBlockHeader() here. This means that if we add a new
    // consensus rule that is enforced in one of those two functions, then we
    // may have let in a block that violates the rule prior to updating the
    // software, and we would NOT be enforcing the rule here. Fully solving
    // upgrade from one software version to the next after a consensus rule
    // change is potentially tricky and issue-specific (see RewindBlockIndex()
    // for one general approach that was used for BIP 141 deployment).
    // Also, currently the rule against blocks more than 2 hours in the future
    // is enforced in ContextualCheckBlockHeader(); we wouldn't want to
    // re-enforce that rule here (at least until we make it impossible for
    // GetAdjustedTime() to go backward).
    if (!CheckBlock(block, state, chainparams.GetConsensus(), !fJustCheck, !fJustCheck)) {
        if (state.GetResult() == BlockValidationResult::BLOCK_MUTATED) {
            // We don't write down blocks to disk if they may have been
            // corrupted, so this should be impossible unless we're having hardware
            // problems.
            return AbortNode(state, "Corrupt block found indicating potential hardware failure; shutting down");
        }
        return error("%s: Consensus::CheckBlock: %s", __func__, state.ToString());
    }

    if (block.IsProofOfStake()) {
        pindex->bnStakeModifier = ComputeStakeModifierV2(pindex->pprev, pindex->prevoutStake.hash);
        setDirtyBlockIndex.insert(pindex);

        uint256 hashProof, targetProofOfStake;
        if (!CheckProofOfStake(state, pindex->pprev, *block.vtx[0], block.nTime, block.nBits, hashProof, targetProofOfStake)) {
            return error("%s: Check proof of stake failed.", __func__);
        }
    }

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    uint256 blockHash = block.GetHash();
    bool fIsGenesisBlock = blockHash == chainparams.GetConsensus().hashGenesisBlock;
    nBlocksTotal++;

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (!fGhostMode  // genesis coinbase is spendable when in Ghost mode
        && fIsGenesisBlock) {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash(), pindex->nHeight);
        return true;
    }

    bool fScriptChecks = true;
    if (!hashAssumeValid.IsNull()) {
        // We've been configured with the hash of a block which has been externally verified to have a valid history.
        // A suitable default value is included with the software and updated from time to time.  Because validity
        //  relative to a piece of software is an objective fact these defaults can be easily reviewed.
        // This setting doesn't force the selection of any particular chain but makes validating some faster by
        //  effectively caching the result of part of the verification.
        BlockMap::const_iterator  it = m_blockman.m_block_index.find(hashAssumeValid);
        if (it != m_blockman.m_block_index.end()) {
            if (it->second->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->nChainWork >= nMinimumChainWork) {
                // This block is a member of the assumed verified chain and an ancestor of the best header.
                // Script verification is skipped when connecting blocks under the
                // assumevalid block. Assuming the assumevalid block is valid this
                // is safe because block merkle hashes are still computed and checked,
                // Of course, if an assumed valid block is invalid due to false scriptSigs
                // this optimization would allow an invalid chain to be accepted.
                // The equivalent time check discourages hash power from extorting the network via DOS attack
                //  into accepting an invalid block through telling users they must manually set assumevalid.
                //  Requiring a software change or burying the invalid block, regardless of the setting, makes
                //  it hard to hide the implication of the demand.  This also avoids having release candidates
                //  that are hardly doing any signature verification at all in testing without having to
                //  artificially set the default assumed verified block further back.
                // The test against nMinimumChainWork prevents the skipping when denied access to any chain at
                //  least as good as the expected chain.
                fScriptChecks = (GetBlockProofEquivalentTime(*pindexBestHeader, *pindex, *pindexBestHeader, chainparams.GetConsensus()) <= 60 * 60 * 24 * 7 * 2);
            }
        }
    }

    int64_t nTime1 = GetTimeMicros(); nTimeCheck += nTime1 - nTimeStart;
    LogPrint(BCLog::BENCH, "    - Sanity checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime1 - nTimeStart), nTimeCheck * MICRO, nTimeCheck * MILLI / nBlocksTotal);

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30, CVE-2012-1909, and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = fGhostMode || (!((pindex->nHeight==91842 && pindex->GetBlockHash() == uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                           (pindex->nHeight==91880 && pindex->GetBlockHash() == uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"))));

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried it's no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.

    // BIP34 requires that a block at height X (block X) has its coinbase
    // scriptSig start with a CScriptNum of X (indicated height X).  The above
    // logic of no longer requiring BIP30 once BIP34 activates is flawed in the
    // case that there is a block X before the BIP34 height of 227,931 which has
    // an indicated height Y where Y is greater than X.  The coinbase for block
    // X would also be a valid coinbase for block Y, which could be a BIP30
    // violation.  An exhaustive search of all mainnet coinbases before the
    // BIP34 height which have an indicated height greater than the block height
    // reveals many occurrences. The 3 lowest indicated heights found are
    // 209,921, 490,897, and 1,983,702 and thus coinbases for blocks at these 3
    // heights would be the first opportunity for BIP30 to be violated.

    // The search reveals a great many blocks which have an indicated height
    // greater than 1,983,702, so we simply remove the optimization to skip
    // BIP30 checking for blocks at height 1,983,702 or higher.  Before we reach
    // that block in another 25 years or so, we should take advantage of a
    // future consensus change to do a new and improved version of BIP34 that
    // will actually prevent ever creating any duplicate coinbases in the
    // future.
    static constexpr int BIP34_IMPLIES_BIP30_LIMIT = 1983702;

    // TODO: Remove BIP30 checking from block height 1,983,702 on, once we have a
    // consensus change that ensures coinbases at those heights can not
    // duplicate earlier coinbases.
    if (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT) {
        for (const auto& tx : block.vtx) {
            for (size_t o = 0; o < tx->GetNumVOuts(); o++) {
                if (view.HaveCoin(COutPoint(tx->GetHash(), o))) {
                    LogPrintf("ERROR: ConnectBlock(): tried to overwrite transaction\n");
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-BIP30");
                }
            }
        }
    }

    // Start enforcing BIP68 (sequence locks)
    int nLockTimeFlags = 0;
    if ((fGhostMode && pindex->pprev) || pindex->nHeight >= chainparams.GetConsensus().CSVHeight) {
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Get the script flags for this block
    unsigned int flags = GetBlockScriptFlags(pindex, chainparams.GetConsensus());

    int64_t nTime2 = GetTimeMicros(); nTimeForks += nTime2 - nTime1;
    LogPrint(BCLog::BENCH, "    - Fork checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime2 - nTime1), nTimeForks * MICRO, nTimeForks * MILLI / nBlocksTotal);

    CBlockUndo blockundo;

    // Precomputed transaction data pointers must not be invalidated
    // until after `control` has run the script checks (potentially
    // in multiple threads). Preallocate the vector size so a new allocation
    // doesn't invalidate pointers into the vector, and keep txsdata in scope
    // for as long as `control`.
    CCheckQueueControl<CScriptCheck> control(fScriptChecks && g_parallel_script_checks ? &scriptcheckqueue : nullptr);
    std::vector<PrecomputedTransactionData> txsdata(block.vtx.size());

    std::vector<int> prevheights;
    CAmount nFees = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    int64_t nAnonIn = 0;
    int64_t nStakeReward = 0;

    blockundo.vtxundo.reserve(block.vtx.size() - (fGhostMode ? 0 : 1));

    // NOTE: Be careful tracking coin created, block reward is based on nMoneySupply
    CAmount nMoneyCreated = 0;

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *(block.vtx[i]);
        const uint256 txhash = tx.GetHash();
        nInputs += tx.vin.size();

        TxValidationState tx_state;
        tx_state.SetStateInfo(block.nTime, pindex->nHeight, consensus, fGhostMode, (fBusyImporting && fSkipRangeproof));
        if (!tx.IsCoinBase())
        {
            CAmount txfee = 0;
            if (!Consensus::CheckTxInputs(tx, tx_state, view, pindex->nHeight, txfee)) {
                control.Wait();
                // Any transaction validation failure in ConnectBlock is a block consensus failure
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                            tx_state.GetRejectReason(), tx_state.GetDebugMessage());
                return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), state.ToString());
            }
            if (tx.IsCoinStake())
            {
                // Stake reward is passed back in txfee (nPlainValueOut - nPlainValueIn)
                nStakeReward += txfee;
                nMoneyCreated += nStakeReward;
            } else
            {
                nFees += txfee;
            }
            if (!MoneyRange(nFees)) {
                control.Wait();
                LogPrintf("ERROR: %s: accumulated fee in the block out of range.\n", __func__);
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-accumulated-fee-outofrange");
            }

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set

            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                if (tx.vin[j].IsAnonInput())
                    prevheights[j] = 0;
                else
                    prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex)) {
                control.Wait();
                LogPrintf("ERROR: %s: contains a non-BIP68-final transaction\n", __func__);
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal");
            }

            if (tx.IsGhostVersion()) {
                // Update spent inputs
                for (size_t j = 0; j < tx.vin.size(); j++) {
                    const CTxIn input = tx.vin[j];
                    if (input.IsAnonInput()) {
                        nAnonIn++;
                        continue;
                    }

                    const Coin &coin = view.AccessCoin(input.prevout);

                    if (coin.nType != OUTPUT_CT) {
                        view.spent_cache.emplace_back(input.prevout, SpentCoin(coin, pindex->nHeight));
                    }
                    if (!fAddressIndex && !fSpentIndex) {
                        continue;
                    }

                    const CScript *pScript = &coin.out.scriptPubKey;
                    CAmount nValue = coin.nType == OUTPUT_CT ? 0 : coin.out.nValue;
                    std::vector<uint8_t> hashBytes;
                    int scriptType = 0;

                    if (!ExtractIndexInfo(pScript, scriptType, hashBytes)
                        || scriptType == 0) {
                        continue;
                    }

                    uint256 hashAddress;
                    if (scriptType > 0) {
                        hashAddress = uint256(hashBytes.data(), hashBytes.size());
                    }
                    if (fAddressIndex && scriptType > 0) {
                        // record spending activity
                        view.addressIndex.push_back(std::make_pair(CAddressIndexKey(scriptType, hashAddress, pindex->nHeight, i, txhash, j, true), nValue * -1));
                        // remove address from unspent index
                        view.addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(scriptType, hashAddress, input.prevout.hash, input.prevout.n), CAddressUnspentValue()));
                    }
                    if (fSpentIndex) {
                        CAmount nValue = coin.nType == OUTPUT_CT ? -1 : coin.out.nValue;
                        // add the spent index to determine the txid and input that spent an output
                        // and to find the amount and address from an input
                        view.spentIndex.push_back(std::make_pair(CSpentIndexKey(input.prevout.hash, input.prevout.n), CSpentIndexValue(txhash, j, pindex->nHeight, nValue, scriptType, hashAddress)));
                    }
                }

                if (smsg::fSecMsgEnabled && tx_state.m_funds_smsg) {
                    smsgModule.StoreFundingTx(tx, pindex);
                }
            }
        }

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST) {
            control.Wait();
            LogPrintf("ERROR: ConnectBlock(): too many sigops\n");
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops");
        }

        if (!tx.IsCoinBase())
        {
            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            //TxValidationState tx_state;
            if (fScriptChecks && !CheckInputScripts(tx, tx_state, view, flags, fCacheResults, fCacheResults, txsdata[i], g_parallel_script_checks ? &vChecks : nullptr)) {
                control.Wait();
                // Any transaction validation failure in ConnectBlock is a block consensus failure
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                              tx_state.GetRejectReason(), tx_state.GetDebugMessage());
                return error("ConnectBlock(): CheckInputScripts on %s failed with %s",
                    txhash.ToString(), state.ToString());
            }
            control.Add(vChecks);

            blockundo.vtxundo.push_back(CTxUndo());
            UpdateCoins(tx, view, blockundo.vtxundo.back(), pindex->nHeight);
        } else
        {
            // tx is coinbase
            CTxUndo undoDummy;
            UpdateCoins(tx, view, undoDummy, pindex->nHeight);
            nMoneyCreated += tx.GetValueOut();
        }

        if (view.nLastRCTOutput == 0) {
            view.nLastRCTOutput = pindex->pprev ? pindex->pprev->nAnonOutputs : 0;
        }

        // Index rct outputs and keyimages
        if (tx_state.m_has_anon_output || tx_state.m_has_anon_input) {
            COutPoint op(txhash, 0);
            for (const auto &txin : tx.vin) {
                if (txin.IsAnonInput()) {
                    uint32_t nAnonInputs, nRingSize;
                    txin.GetAnonInfo(nAnonInputs, nRingSize);
                    if (txin.scriptData.stack.size() != 1
                        || txin.scriptData.stack[0].size() != 33 * nAnonInputs) {
                        control.Wait();
                        return error("%s: Bad scriptData stack, %s.", __func__, txhash.ToString());
                    }

                    const std::vector<uint8_t> &vKeyImages = txin.scriptData.stack[0];
                    for (size_t k = 0; k < nAnonInputs; ++k) {
                        const CCmpPubKey &ki = *((CCmpPubKey*)&vKeyImages[k*33]);

                        view.keyImages.push_back(std::make_pair(ki, txhash));
                    }
                }
            }

            for (unsigned int k = 0; k < tx.vpout.size(); k++) {
                if (!tx.vpout[k]->IsType(OUTPUT_RINGCT)) {
                    continue;
                }

                CTxOutRingCT *txout = (CTxOutRingCT*)tx.vpout[k].get();

                int64_t nTestExists;
                if (!fVerifyingDB && pblocktree->ReadRCTOutputLink(txout->pk, nTestExists)) {
                    control.Wait();

                    if (nTestExists > pindex->pprev->nAnonOutputs) {
                        // The anon index can diverge from the chain index if shutdown does not complete
                        LogPrintf("%s: Duplicate anon-output %s, index %d, above last index %d.\n", __func__, HexStr(txout->pk.begin(), txout->pk.end()), nTestExists, pindex->pprev->nAnonOutputs);
                        LogPrintf("Attempting to repair anon index.\n");
                        std::set<CCmpPubKey> setKi; // unused
                        RollBackRCTIndex(pindex->pprev->nAnonOutputs, nTestExists, setKi);
                        return false;
                    }

                    return error("%s: Duplicate anon-output (db) %s, index %d.", __func__, HexStr(txout->pk.begin(), txout->pk.end()), nTestExists);
                }
                if (!fVerifyingDB && view.ReadRCTOutputLink(txout->pk, nTestExists)) {
                    control.Wait();
                    return error("%s: Duplicate anon-output (view) %s, index %d.", __func__, HexStr(txout->pk.begin(), txout->pk.end()), nTestExists);
                }

                op.n = k;
                view.nLastRCTOutput++;
                CAnonOutput ao(txout->pk, txout->commitment, op, pindex->nHeight, 0);

                view.anonOutputLinks[txout->pk] = view.nLastRCTOutput;
                view.anonOutputs.push_back(std::make_pair(view.nLastRCTOutput, ao));
            }
        }

        if (fAddressIndex) {
            // Update outputs for insight
            for (unsigned int k = 0; k < tx.vpout.size(); k++) {
                const CTxOutBase *out = tx.vpout[k].get();

                if (!out->IsType(OUTPUT_STANDARD)
                    && !out->IsType(OUTPUT_CT)) {
                    continue;
                }

                const CScript *pScript;
                std::vector<unsigned char> hashBytes;
                int scriptType = 0;
                CAmount nValue;
                if (!ExtractIndexInfo(out, scriptType, hashBytes, nValue, pScript)
                    || scriptType == 0) {
                    continue;
                }

                // Record receiving activity
                view.addressIndex.push_back(std::make_pair(CAddressIndexKey(scriptType, uint256(hashBytes.data(), hashBytes.size()), pindex->nHeight, i, txhash, k, false), nValue));
                // Record unspent output
                view.addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(scriptType, uint256(hashBytes.data(), hashBytes.size()), txhash, k), CAddressUnspentValue(nValue, *pScript, pindex->nHeight)));
            }
        }
    }

    int64_t nTime3 = GetTimeMicros(); nTimeConnect += nTime3 - nTime2;
    LogPrint(BCLog::BENCH, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs (%.2fms/blk)]\n", (unsigned)block.vtx.size(), MILLI * (nTime3 - nTime2), MILLI * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : MILLI * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);


    if (!control.Wait()) {
        LogPrintf("ERROR: %s: CheckQueue failed\n", __func__);
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "block-validation-failed");
    }

    if (fGhostMode) {
        if (block.IsProofOfStake()) { // Only the genesis block isn't proof of stake
            CTransactionRef txCoinstake = block.vtx[0];
            CTransactionRef txPrevCoinstake = nullptr;
            const DevFundSettings *pDevFundSettings = chainparams.GetDevFundSettings(block.nTime);
            const CAmount nCalculatedStakeReward = Params().GetProofOfStakeReward(pindex->pprev, nFees); // stake_test

            if (block.nTime >= consensus.smsg_fee_time) {
                CAmount smsg_fee_new = consensus.smsg_fee_msg_per_day_per_k, smsg_fee_prev = consensus.smsg_fee_msg_per_day_per_k;
                if (pindex->pprev->nHeight > 0 // Skip genesis block (POW)
                    && pindex->pprev->nTime >= consensus.smsg_fee_time) {
                    if (!coinStakeCache.GetCoinStake(pindex->pprev->GetBlockHash(), txPrevCoinstake)
                        || !txPrevCoinstake->GetSmsgFeeRate(smsg_fee_prev)) {
                        LogPrintf("ERROR: %s: Failed to get previous smsg fee.\n", __func__);
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-smsg-fee-prev");
                    }
                }

                if (!txCoinstake->GetSmsgFeeRate(smsg_fee_new)) {
                    LogPrintf("ERROR: %s: Failed to get smsg fee.\n", __func__);
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-smsg-fee");
                }
                if (smsg_fee_new < 1) {
                    LogPrintf("ERROR: %s: Smsg fee < 1.\n", __func__);
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-smsg-fee");
                }
                int64_t delta = std::abs(smsg_fee_new - smsg_fee_prev);
                int64_t max_delta = chainparams.GetMaxSmsgFeeRateDelta(smsg_fee_prev);
                if (delta > max_delta) {
                    LogPrintf("ERROR: %s: Bad smsg-fee (delta=%d, max_delta=%d)\n", __func__, delta, max_delta);
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-smsg-fee");
                }
            }

            if (block.nTime >= consensus.smsg_difficulty_time) {
                uint32_t smsg_difficulty_new = consensus.smsg_min_difficulty, smsg_difficulty_prev = consensus.smsg_min_difficulty;
                if (pindex->pprev->nHeight > 0 // Skip genesis block (POW)
                    && pindex->pprev->nTime >= consensus.smsg_difficulty_time) {
                    if (!coinStakeCache.GetCoinStake(pindex->pprev->GetBlockHash(), txPrevCoinstake)
                        || !txPrevCoinstake->GetSmsgDifficulty(smsg_difficulty_prev)) {
                        LogPrintf("ERROR: %s: Failed to get previous smsg difficulty.\n", __func__);
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-smsg-diff-prev");
                    }
                }

                if (!txCoinstake->GetSmsgDifficulty(smsg_difficulty_new)) {
                    LogPrintf("ERROR: %s: Failed to get smsg difficulty.\n", __func__);
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-smsg-diff");
                }
                if (smsg_difficulty_new < 1 || smsg_difficulty_new > consensus.smsg_min_difficulty) {

                    LogPrintf("ERROR: %s: Smsg difficulty out of range.\n", __func__);
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-smsg-diff");
                }
                int delta = int(smsg_difficulty_prev) - int(smsg_difficulty_new);
                if (abs(delta) > int(consensus.smsg_difficulty_max_delta)) {
                    LogPrintf("ERROR: %s: Smsg difficulty change out of range.\n", __func__);
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-smsg-diff");
                }
            }

            if (!pDevFundSettings || pDevFundSettings->nMinDevStakePercent <= 0) {
                if (nStakeReward < 0 || nStakeReward > nCalculatedStakeReward) {
                    LogPrintf("ERROR: %s: Coinstake pays too much(actual=%d vs calculated=%d)\n", __func__, nStakeReward, nCalculatedStakeReward);
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-amount");
                }
            } else {
                assert(pDevFundSettings->nMinDevStakePercent <= 100);

                CAmount nDevBfwd = 0, nDevCfwdCheck = 0;
                CAmount nMinDevPart = (nCalculatedStakeReward * pDevFundSettings->nMinDevStakePercent) / 100;
                CAmount nMaxHolderPart = nCalculatedStakeReward - nMinDevPart;
                if (nMinDevPart < 0 || nMaxHolderPart < 0) {
                    LogPrintf("ERROR: %s: Bad coinstake split amount (foundation=%d vs reward=%d)\n", __func__, nMinDevPart, nMaxHolderPart);
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-amount");
                }

                if (pindex->pprev->nHeight > 0) { // Genesis block is pow
                    if (!txPrevCoinstake
                        && !coinStakeCache.GetCoinStake(pindex->pprev->GetBlockHash(), txPrevCoinstake)) {
                        LogPrintf("ERROR: %s: Failed to get previous coinstake.\n", __func__);
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-prev");
                    }

                    assert(txPrevCoinstake->IsCoinStake()); // Sanity check
                    if (!txPrevCoinstake->GetDevFundCfwd(nDevBfwd)) {
                        nDevBfwd = 0;
                    }
                }

                if (pindex->nHeight % pDevFundSettings->nDevOutputPeriod == 0) {
                    // Fund output must exist and match cfwd, cfwd data output must be unset
                    // nStakeReward must == nDevBfwd + nCalculatedStakeReward

                    if (nStakeReward != nDevBfwd + nCalculatedStakeReward) {
                        LogPrintf("ERROR: %s: Bad stake-reward (actual=%d vs expected=%d)\n", __func__, nStakeReward, nDevBfwd + nCalculatedStakeReward);
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-amount");
                    }

                    CTxDestination dfDest = CBitcoinAddress(pDevFundSettings->sDevFundAddresses).Get();
                    if (dfDest.type() == typeid(CNoDestination)) {
                        return error("%s: Failed to get foundation fund destination: %s.", __func__, pDevFundSettings->sDevFundAddresses);
                    }
                    CScript devFundScriptPubKey = GetScriptForDestination(dfDest);

                    // Output 1 must be to the dev fund
                    const CTxOutStandard *outputDF = txCoinstake->vpout[1]->GetStandardOutput();
                    if (!outputDF) {
                        LogPrintf("ERROR: %s: Bad foundation fund output.\n", __func__);
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs");
                    }
                    if (outputDF->scriptPubKey != devFundScriptPubKey) {
                        LogPrintf("ERROR: %s: Bad foundation fund output script.\n", __func__);
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs");
                    }
                    if (outputDF->nValue < nDevBfwd + nMinDevPart) { // Max value is clamped already
                        LogPrintf("ERROR: %s: Bad foundation-reward (actual=%d vs minfundpart=%d)\n", __func__, nStakeReward, nDevBfwd + nMinDevPart);
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-fund-amount");
                    }
                    if (txCoinstake->GetDevFundCfwd(nDevCfwdCheck)) {
                        LogPrintf("ERROR: %s: Coinstake foundation cfwd must be unset.\n", __func__);
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-cfwd");
                    }
                } else {
                    // Ensure cfwd data output is correct and nStakeReward is <= nHolderPart
                    // cfwd must == nDevBfwd + (nCalculatedStakeReward - nStakeReward) // Allowing users to set a higher split

                    if (nStakeReward < 0 || nStakeReward > nMaxHolderPart) {
                        LogPrintf("ERROR: %s: Bad stake-reward (actual=%d vs maxholderpart=%d)\n", __func__, nStakeReward, nMaxHolderPart);
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-amount");
                    }
                    CAmount nDevCfwd = nDevBfwd + nCalculatedStakeReward - nStakeReward;
                    if (!txCoinstake->GetDevFundCfwd(nDevCfwdCheck)
                        || nDevCfwdCheck != nDevCfwd) {
                        LogPrintf("ERROR: %s: Coinstake foundation fund carried forward mismatch (actual=%d vs expected=%d)\n", __func__, nDevCfwdCheck, nDevCfwd);
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-cfwd");
                    }
                }

                coinStakeCache.InsertCoinStake(blockHash, txCoinstake);
            }
        } else {
            if (block.GetHash() != chainparams.GenesisBlock().GetHash()) {
                LogPrintf("ERROR: %s: Block isn't coinstake or genesis.\n", __func__);
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs");
            }
        }
    } else {
        CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, chainparams.GetConsensus());
        if (block.vtx[0]->GetValueOut() > blockReward) {
            LogPrintf("ERROR: ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)\n", block.vtx[0]->GetValueOut(), blockReward);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-amount");
        }
    }

    int64_t nTime4 = GetTimeMicros(); nTimeVerify += nTime4 - nTime2;
    LogPrint(BCLog::BENCH, "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs (%.2fms/blk)]\n", nInputs - 1, MILLI * (nTime4 - nTime2), nInputs <= 1 ? 0 : MILLI * (nTime4 - nTime2) / (nInputs-1), nTimeVerify * MICRO, nTimeVerify * MILLI / nBlocksTotal);

    if (fJustCheck)
        return true;

    pindex->nMoneySupply = (pindex->pprev ? pindex->pprev->nMoneySupply : 0) + nMoneyCreated;
    pindex->nAnonOutputs = view.nLastRCTOutput;
    setDirtyBlockIndex.insert(pindex); // pindex has changed, must save to disk

    if ((!fIsGenesisBlock || fGhostMode)
     && !WriteUndoDataForBlock(blockundo, state, pindex, chainparams))
        return false;

    if (!pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }


    if (fTimestampIndex) {
        unsigned int logicalTS = pindex->nTime;
        unsigned int prevLogicalTS = 0;

        // Retrieve logical timestamp of the previous block
        if (pindex->pprev) {
            if (!pblocktree->ReadTimestampBlockIndex(pindex->pprev->GetBlockHash(), prevLogicalTS)) {
                LogPrintf("%s: Failed to read previous block's logical timestamp\n", __func__);
            }
        }

        if (logicalTS <= prevLogicalTS) {
            logicalTS = prevLogicalTS + 1;
            LogPrintf("%s: Previous logical timestamp is newer Actual[%d] prevLogical[%d] Logical[%d]\n", __func__, pindex->nTime, prevLogicalTS, logicalTS);
        }

        if (!pblocktree->WriteTimestampIndex(CTimestampIndexKey(logicalTS, pindex->GetBlockHash()))) {
            return AbortNode(state, "Failed to write timestamp index");
        }

        if (!pblocktree->WriteTimestampBlockIndex(CTimestampBlockIndexKey(pindex->GetBlockHash()), CTimestampBlockIndexValue(logicalTS))) {
            return AbortNode(state, "Failed to write blockhash index");
        }
    }

    assert(pindex->phashBlock);
    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash(), pindex->nHeight);

    int64_t nTime5 = GetTimeMicros(); nTimeIndex += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "    - Index writing: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime5 - nTime4), nTimeIndex * MICRO, nTimeIndex * MILLI / nBlocksTotal);

    int64_t nTime6 = GetTimeMicros(); nTimeCallbacks += nTime6 - nTime5;
    LogPrint(BCLog::BENCH, "    - Callbacks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime6 - nTime5), nTimeCallbacks * MICRO, nTimeCallbacks * MILLI / nBlocksTotal);

    return true;
}

CoinsCacheSizeState CChainState::GetCoinsCacheSizeState(const CTxMemPool& tx_pool)
{
    return this->GetCoinsCacheSizeState(
        tx_pool,
        nCoinCacheUsage,
        gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000);
}

CoinsCacheSizeState CChainState::GetCoinsCacheSizeState(
    const CTxMemPool& tx_pool,
    size_t max_coins_cache_size_bytes,
    size_t max_mempool_size_bytes)
{
    int64_t nMempoolUsage = tx_pool.DynamicMemoryUsage();
    int64_t cacheSize = CoinsTip().DynamicMemoryUsage();
    int64_t nTotalSpace =
        max_coins_cache_size_bytes + std::max<int64_t>(max_mempool_size_bytes - nMempoolUsage, 0);

    //! No need to periodic flush if at least this much space still available.
    static constexpr int64_t MAX_BLOCK_COINSDB_USAGE_BYTES = 10 * 1024 * 1024;  // 10MB
    int64_t large_threshold =
        std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE_BYTES);

    if (cacheSize > nTotalSpace) {
        LogPrintf("Cache size (%s) exceeds total space (%s)\n", cacheSize, nTotalSpace);
        return CoinsCacheSizeState::CRITICAL;
    } else if (cacheSize > large_threshold) {
        return CoinsCacheSizeState::LARGE;
    }
    return CoinsCacheSizeState::OK;
}

bool CChainState::FlushStateToDisk(
    const CChainParams& chainparams,
    BlockValidationState &state,
    FlushStateMode mode,
    int nManualPruneHeight)
{
    LOCK(cs_main);
    assert(this->CanFlushToDisk());
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    std::set<int> setFilesToPrune;
    bool full_flush_completed = false;

    const size_t coins_count = CoinsTip().GetCacheSize();
    const size_t coins_mem_usage = CoinsTip().DynamicMemoryUsage();

    try {
    {
        bool fFlushForPrune = false;
        bool fDoFullFlush = false;
        CoinsCacheSizeState cache_state = GetCoinsCacheSizeState(::mempool);
        LOCK(cs_LastBlockFile);
        if (fPruneMode && (fCheckForPruning || nManualPruneHeight > 0) && !fReindex) {
            if (nManualPruneHeight > 0) {
                LOG_TIME_MILLIS_WITH_CATEGORY("find files to prune (manual)", BCLog::BENCH);

                FindFilesToPruneManual(setFilesToPrune, nManualPruneHeight);
            } else {
                LOG_TIME_MILLIS_WITH_CATEGORY("find files to prune", BCLog::BENCH);

                FindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
                fCheckForPruning = false;
            }
            if (!setFilesToPrune.empty()) {
                fFlushForPrune = true;
                if (!fHavePruned) {
                    pblocktree->WriteFlag("prunedblockfiles", true);
                    fHavePruned = true;
                }
            }
        }
        int64_t nNow = GetTimeMicros();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite == 0) {
            nLastWrite = nNow;
        }
        if (nLastFlush == 0) {
            nLastFlush = nNow;
        }
        // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now (not in the middle of a block processing).
        bool fCacheLarge = mode == FlushStateMode::PERIODIC && cache_state >= CoinsCacheSizeState::LARGE;
        // The cache is over the limit, we have to write now.
        bool fCacheCritical = mode == FlushStateMode::IF_NEEDED && cache_state >= CoinsCacheSizeState::CRITICAL;
        // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
        bool fPeriodicWrite = mode == FlushStateMode::PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FlushStateMode::PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
        // Combine all conditions that result in a full cache flush.
        fDoFullFlush = (mode == FlushStateMode::ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
        // Write blocks and block index to disk.
        if (fDoFullFlush || fPeriodicWrite) {
            // Depend on nMinDiskSpace to ensure we can write block index
            if (!CheckDiskSpace(GetBlocksDir())) {
                return AbortNode(state, "Disk space is too low!", _("Error: Disk space is too low!").translated, CClientUIInterface::MSG_NOPREFIX);
            }
            {
                LOG_TIME_MILLIS_WITH_CATEGORY("write block and undo data to disk", BCLog::BENCH);

                // First make sure all block and undo data is flushed to disk.
                FlushBlockFile();
            }

            // Then update all block file information (which may refer to block and undo files).
            {
                LOG_TIME_MILLIS_WITH_CATEGORY("write block index to disk", BCLog::BENCH);

                std::vector<std::pair<int, const CBlockFileInfo*> > vFiles;
                vFiles.reserve(setDirtyFileInfo.size());
                for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end(); ) {
                    vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                    setDirtyFileInfo.erase(it++);
                }
                std::vector<const CBlockIndex*> vBlocks;
                vBlocks.reserve(setDirtyBlockIndex.size());
                for (std::set<CBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end(); ) {
                    if ((*it)->nFlags & BLOCK_ACCEPTED) {
                        vBlocks.push_back(*it);
                    }
                    setDirtyBlockIndex.erase(it++);
                }
                if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) {
                    return AbortNode(state, "Failed to write to block index database");
                }
            }
            // Finally remove any pruned files
            if (fFlushForPrune) {
                LOG_TIME_MILLIS_WITH_CATEGORY("unlink pruned files", BCLog::BENCH);

                UnlinkPrunedFiles(setFilesToPrune);
            }
            nLastWrite = nNow;
        }
        // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush && !CoinsTip().GetBestBlock().IsNull()) {
            LOG_TIME_SECONDS(strprintf("write coins cache to disk (%d coins, %.2fkB)",
                coins_count, coins_mem_usage / 1000));

            // Typical Coin structures on disk are around 48 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(GetDataDir(), 48 * 2 * 2 * CoinsTip().GetCacheSize())) {
                return AbortNode(state, "Disk space is too low!", _("Error: Disk space is too low!").translated, CClientUIInterface::MSG_NOPREFIX);
            }
            // Flush the chainstate (which may refer to block index entries).
            if (!CoinsTip().Flush())
                return AbortNode(state, "Failed to write to coin database");
            nLastFlush = nNow;
            full_flush_completed = true;
        }
    }
    if (full_flush_completed) {
        // Update best block in wallet (so we can detect restored wallets).
        GetMainSignals().ChainStateFlushed(m_chain.GetLocator());
    }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void CChainState::ForceFlushStateToDisk() {
    BlockValidationState state;
    const CChainParams& chainparams = Params();
    if (!this->FlushStateToDisk(chainparams, state, FlushStateMode::ALWAYS)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, state.ToString());
    }
}

void CChainState::PruneAndFlush() {
    BlockValidationState state;
    fCheckForPruning = true;
    const CChainParams& chainparams = Params();

    if (!this->FlushStateToDisk(chainparams, state, FlushStateMode::NONE)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, state.ToString());
    }
}

static void DoWarning(const std::string& strWarning)
{
    static bool fWarned = false;
    SetMiscWarning(strWarning);
    if (!fWarned) {
        AlertNotify(strWarning);
        fWarned = true;
    }
}

static void ClearSpentCache(CDBBatch &batch, int height)
{
    CBlockIndex* pblockindex = ::ChainActive()[height];
    if (!pblockindex) {
        return;
    }
    CBlock block;
    if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
        LogPrintf("%s: failed read block from disk (%d, %s)\n", __func__, height, pblockindex->GetBlockHash().ToString());
        return;
    }
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = *(block.vtx[i]);
        for (const auto &txin : tx.vin) {
            if (!txin.IsAnonInput()) {
                batch.Erase(std::make_pair(DB_SPENTCACHE, txin.prevout));
            }
        }
    }
}

bool FlushView(CCoinsViewCache *view, BlockValidationState& state, bool fDisconnecting)
{
    if (!view->Flush())
        return false;

    if (fAddressIndex) {
        if (fDisconnecting) {
            if (!pblocktree->EraseAddressIndex(view->addressIndex)) {
                return AbortNode(state, "Failed to delete address index");
            }
        } else {
            if (!pblocktree->WriteAddressIndex(view->addressIndex)) {
                return AbortNode(state, "Failed to write address index");
            }
        }
        if (!pblocktree->UpdateAddressUnspentIndex(view->addressUnspentIndex)) {
            return AbortNode(state, "Failed to write address unspent index");
        }
    }

    if (fSpentIndex) {
        if (!pblocktree->UpdateSpentIndex(view->spentIndex)) {
            return AbortNode(state, "Failed to write transaction index");
        }
    }

    view->addressIndex.clear();
    view->addressUnspentIndex.clear();
    view->spentIndex.clear();

    if (fDisconnecting) {
        for (const auto &it : view->keyImages) {
            if (!pblocktree->EraseRCTKeyImage(it.first)) {
                return error("%s: EraseRCTKeyImage failed, txn %s.", __func__, it.second.ToString());
            }
        }
        for (const auto &it : view->anonOutputLinks) {
            if (!pblocktree->EraseRCTOutput(it.second)) {
                return error("%s: EraseRCTOutput failed.", __func__);
            }
            if (!pblocktree->EraseRCTOutputLink(it.first)) {
                return error("%s: EraseRCTOutputLink failed.", __func__);
            }
        }
        for (const auto &it : view->spent_cache) {
            if (!pblocktree->EraseSpentCache(it.first)) {
                return error("%s: EraseSpentCache failed.", __func__);
            }
        }
    } else {
        CDBBatch batch(*pblocktree);

        for (const auto &it : view->keyImages) {
            batch.Write(std::make_pair(DB_RCTKEYIMAGE, it.first), it.second);
        }
        for (const auto &it : view->anonOutputs) {
            batch.Write(std::make_pair(DB_RCTOUTPUT, it.first), it.second);
        }
        for (const auto &it : view->anonOutputLinks) {
            batch.Write(std::make_pair(DB_RCTOUTPUT_LINK, it.first), it.second);
        }
        for (const auto &it : view->spent_cache) {
            batch.Write(std::make_pair(DB_SPENTCACHE, it.first), it.second);
        }
        if (state.m_spend_height > MIN_BLOCKS_TO_KEEP) {
            ClearSpentCache(batch, state.m_spend_height - (MIN_BLOCKS_TO_KEEP+1));
        }
        if (!pblocktree->WriteBatch(batch)) {
            return error("%s: Write index data failed.", __func__);
        }
    }

    view->nLastRCTOutput = 0;
    view->anonOutputs.clear();
    view->anonOutputLinks.clear();
    view->keyImages.clear();
    view->spent_cache.clear();

    return true;
};

/** Private helper function that concatenates warning messages. */
static void AppendWarning(std::string& res, const std::string& warn)
{
    if (!res.empty()) res += ", ";
    res += warn;
}

/** Check warning conditions and do some notifications on new chain tip set. */
void UpdateTip(const CBlockIndex* pindexNew, const CChainParams& chainParams)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    // New best block
    mempool.AddTransactionsUpdated(1);

    {
        LOCK(g_best_block_mutex);
        g_best_block = pindexNew->GetBlockHash();
        g_best_block_cv.notify_all();
    }

    std::string warningMessages;
    if (!::ChainstateActive().IsInitialBlockDownload())
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexNew;
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
            WarningBitsConditionChecker checker(bit);
            ThresholdState state = checker.GetStateFor(pindex, chainParams.GetConsensus(), warningcache[bit]);
            if (state == ThresholdState::ACTIVE || state == ThresholdState::LOCKED_IN) {
                const std::string strWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)").translated, bit);
                if (state == ThresholdState::ACTIVE) {
                    DoWarning(strWarning);
                } else {
                    AppendWarning(warningMessages, strWarning);
                }
            }
        }
        // Check the version of the last 100 blocks to see if we need to upgrade:
        for (int i = 0; i < 100 && pindex != nullptr; i++)
        {
            if (fGhostMode)
            {
                if (pindex->nVersion > GHOST_BLOCK_VERSION)
                    ++nUpgraded;
            } else
            {
                int32_t nExpectedVersion = ComputeBlockVersion(pindex->pprev, chainParams.GetConsensus());
                if (pindex->nVersion > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (pindex->nVersion & ~nExpectedVersion) != 0)
                    ++nUpgraded;
            }
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            AppendWarning(warningMessages, strprintf(_("%d of last 100 blocks have unexpected version").translated, nUpgraded));
    }
    LogPrintf("%s: new best=%s height=%d version=0x%08x log2_work=%.8g tx=%lu date='%s' progress=%f cache=%.1fMiB(%utxo)%s\n", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight, pindexNew->nVersion,
      log(pindexNew->nChainWork.getdouble())/log(2.0), (unsigned long)pindexNew->nChainTx,
      FormatISO8601DateTime(pindexNew->GetBlockTime()),
      GuessVerificationProgress(chainParams.TxData(), pindexNew), ::ChainstateActive().CoinsTip().DynamicMemoryUsage() * (1.0 / (1<<20)), ::ChainstateActive().CoinsTip().GetCacheSize(),
      !warningMessages.empty() ? strprintf(" warning='%s'", warningMessages) : "");

}

/** Disconnect m_chain's tip.
  * After calling, the mempool will be in an inconsistent state, with
  * transactions from disconnected blocks being added to disconnectpool.  You
  * should make the mempool consistent again by calling UpdateMempoolForReorg.
  * with cs_main held.
  *
  * If disconnectpool is nullptr, then no disconnected transactions are added to
  * disconnectpool (note that the caller is responsible for mempool consistency
  * in any case).
  */
bool CChainState::DisconnectTip(BlockValidationState& state, const CChainParams& chainparams, DisconnectedBlockTransactions *disconnectpool)
{
    CBlockIndex *pindexDelete = m_chain.Tip();
    assert(pindexDelete);
    // Read block from disk.
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock& block = *pblock;
    if (!ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()))
        return error("DisconnectTip(): Failed to read block");
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(&CoinsTip());
        assert(view.GetBestBlock() == pindexDelete->GetBlockHash());
        if (DisconnectBlock(block, pindexDelete, view) != DISCONNECT_OK)
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        bool flushed = FlushView(&view, state, true);
        assert(flushed);
    }
    LogPrint(BCLog::BENCH, "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * MILLI);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::IF_NEEDED))
        return false;

    if (disconnectpool) {
        // Save transactions to re-add to mempool at end of reorg
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            disconnectpool->addTransaction(*it);
        }
        while (disconnectpool->DynamicMemoryUsage() > MAX_DISCONNECTED_TX_POOL_SIZE * 1000) {
            // Drop the earliest entry, and remove its children from the mempool.
            auto it = disconnectpool->queuedTx.get<insertion_order>().begin();
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
            disconnectpool->removeEntry(it);
        }
    }

    m_chain.SetTip(pindexDelete->pprev);

    UpdateTip(pindexDelete->pprev, chainparams);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    GetMainSignals().BlockDisconnected(pblock, pindexDelete);
    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;

struct PerBlockConnectTrace {
    CBlockIndex* pindex = nullptr;
    std::shared_ptr<const CBlock> pblock;
    PerBlockConnectTrace() {}
};
/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 *
 * This class is single-use, once you call GetBlocksConnected() you have to throw
 * it away and make a new one.
 */
class ConnectTrace {
private:
    std::vector<PerBlockConnectTrace> blocksConnected;

public:
    explicit ConnectTrace() : blocksConnected(1) {}

    void BlockConnected(CBlockIndex* pindex, std::shared_ptr<const CBlock> pblock) {
        assert(!blocksConnected.back().pindex);
        assert(pindex);
        assert(pblock);
        blocksConnected.back().pindex = pindex;
        blocksConnected.back().pblock = std::move(pblock);
        blocksConnected.emplace_back();
    }

    std::vector<PerBlockConnectTrace>& GetBlocksConnected() {
        // We always keep one extra block at the end of our list because
        // blocks are added after all the conflicted transactions have
        // been filled in. Thus, the last entry should always be an empty
        // one waiting for the transactions from the next block. We pop
        // the last entry here to make sure the list we return is sane.
        assert(!blocksConnected.back().pindex);
        blocksConnected.pop_back();
        return blocksConnected;
    }
};

/**
 * Connect a new block to m_chain. pblock is either nullptr or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 *
 * The block is added to connectTrace if connection succeeds.
 */
bool CChainState::ConnectTip(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool)
{
    assert(pindexNew->pprev == m_chain.Tip());
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    std::shared_ptr<const CBlock> pthisBlock;
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        if (!ReadBlockFromDisk(*pblockNew, pindexNew, chainparams.GetConsensus()))
            return AbortNode(state, "Failed to read block");
        pthisBlock = pblockNew;
    } else {
        pthisBlock = pblock;
    }
    const CBlock& blockConnecting = *pthisBlock;
    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros(); nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;

    LogPrint(BCLog::BENCH, "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * MILLI, nTimeReadFromDisk * MICRO);
    setConnectKi.clear();
    {
        CCoinsViewCache view(&CoinsTip());
        bool rv = ConnectBlock(blockConnecting, state, pindexNew, view, chainparams);
        if (pindexNew->nFlags & BLOCK_FAILED_DUPLICATE_STAKE)
            state.nFlags |= BLOCK_FAILED_DUPLICATE_STAKE;
        GetMainSignals().BlockChecked(blockConnecting, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, blockConnecting, state);
            return error("%s: ConnectBlock %s failed, %s", __func__, pindexNew->GetBlockHash().ToString(), state.ToString());
        }
        nTime3 = GetTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        assert(nBlocksTotal > 0);
        LogPrint(BCLog::BENCH, "  - Connect total: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime3 - nTime2) * MILLI, nTimeConnectTotal * MICRO, nTimeConnectTotal * MILLI / nBlocksTotal);
        bool flushed = FlushView(&view, state, false);
        assert(flushed);
    }
    int64_t nTime4 = GetTimeMicros(); nTimeFlush += nTime4 - nTime3;
    LogPrint(BCLog::BENCH, "  - Flush: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime4 - nTime3) * MILLI, nTimeFlush * MICRO, nTimeFlush * MILLI / nBlocksTotal);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::IF_NEEDED))
    {
        //RollBackRCTIndex(nLastValidRCTOutput, setConnectKi);
        return false;
    }
    int64_t nTime5 = GetTimeMicros(); nTimeChainState += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "  - Writing chainstate: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime5 - nTime4) * MILLI, nTimeChainState * MICRO, nTimeChainState * MILLI / nBlocksTotal);
    // Remove conflicting transactions from the mempool.;
    mempool.removeForBlock(blockConnecting.vtx, pindexNew->nHeight);
    disconnectpool.removeForBlock(blockConnecting.vtx);
    // Update m_chain & related variables.
    m_chain.SetTip(pindexNew);
    UpdateTip(pindexNew, chainparams);

    int64_t nTime6 = GetTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    LogPrint(BCLog::BENCH, "  - Connect postprocess: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime5) * MILLI, nTimePostConnect * MICRO, nTimePostConnect * MILLI / nBlocksTotal);
    LogPrint(BCLog::BENCH, "- Connect block: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime1) * MILLI, nTimeTotal * MICRO, nTimeTotal * MILLI / nBlocksTotal);

    connectTrace.BlockConnected(pindexNew, std::move(pthisBlock));
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
CBlockIndex* CChainState::FindMostWorkChain() {
    do {
        CBlockIndex *pindexNew = nullptr;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return nullptr;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !m_chain.Contains(pindexTest)) {
            assert(pindexTest->HaveTxsDownloaded() || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);

            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (pindexBestInvalid == nullptr || pindexNew->nChainWork > pindexBestInvalid->nChainWork))
                    pindexBestInvalid = pindexNew;
                CBlockIndex *pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedChain) {

                        if (pindexTest->nFlags & BLOCK_FAILED_DUPLICATE_STAKE)
                            pindexFailed->nFlags |= BLOCK_FAILED_DUPLICATE_STAKE;

                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to m_blocks_unlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        m_blockman.m_blocks_unlinked.insert(
                            std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while(true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
void CChainState::PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, m_chain.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either nullptr or a pointer to a CBlock corresponding to pindexMostWork.
 *
 * @returns true unless a system error occurred
 */
bool CChainState::ActivateBestChainStep(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace)
{
    AssertLockHeld(cs_main);

    const CBlockIndex *pindexOldTip = m_chain.Tip();
    const CBlockIndex *pindexFork = m_chain.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    while (m_chain.Tip() && m_chain.Tip() != pindexFork) {
        if (!DisconnectTip(state, chainparams, &disconnectpool)) {
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            UpdateMempoolForReorg(disconnectpool, false);

            // If we're unable to disconnect a block during normal operation,
            // then that is a failure of our local system -- we should abort
            // rather than stay on a less work chain.
            AbortNode(state, "Failed to disconnect block; see debug.log for details");
            return false;
        }
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        for (CBlockIndex *pindexConnect : reverse_iterate(vpindexToConnect)) {
            if (!ConnectTip(state, chainparams, pindexConnect, pindexConnect == pindexMostWork ? pblock : std::shared_ptr<const CBlock>(), connectTrace, disconnectpool)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
                        InvalidChainFound(vpindexToConnect.front());
                    }
                    state = BlockValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    // Make the mempool consistent with the current tip, just in case
                    // any observers try to use it before shutdown.
                    UpdateMempoolForReorg(disconnectpool, false);
                    return false;
                }
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip || m_chain.Tip()->nChainWork > pindexOldTip->nChainWork) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected) {
        // If any blocks were disconnected, disconnectpool may be non empty.  Add
        // any disconnected transactions back to the mempool.
        UpdateMempoolForReorg(disconnectpool, true);
    }
    mempool.check(&CoinsTip());


    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        CheckForkWarningConditions();

    return true;
}

static bool NotifyHeaderTip() LOCKS_EXCLUDED(cs_main) {
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static CBlockIndex* pindexHeaderOld = nullptr;
    CBlockIndex* pindexHeader = nullptr;
    {
        LOCK(cs_main);
        pindexHeader = pindexBestHeader;

        if (pindexHeader != pindexHeaderOld) {
            fNotify = true;
            fInitialBlockDownload = ::ChainstateActive().IsInitialBlockDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(fInitialBlockDownload, pindexHeader);
    }
    return fNotify;
}

void CheckDelayedBlocks(const CChainParams& chainparams, const uint256 &block_hash) LOCKS_EXCLUDED(cs_main);

static void LimitValidationInterfaceQueue() LOCKS_EXCLUDED(cs_main) {
    AssertLockNotHeld(cs_main);

    if (GetMainSignals().CallbacksPending() > 10) {
        SyncWithValidationInterfaceQueue();
    }
}

bool CChainState::ActivateBestChain(BlockValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock) {
    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!
    AssertLockNotHeld(cs_main);

    // ABC maintains a fair degree of expensive-to-calculate internal state
    // because this function periodically releases cs_main so that it does not lock up other threads for too long
    // during large connects - and to allow for e.g. the callback queue to drain
    // we use m_cs_chainstate to enforce mutual exclusion so that only one caller may execute this function at a time
    LOCK(m_cs_chainstate);

    CBlockIndex *pindexMostWork = nullptr;
    CBlockIndex *pindexNewTip = nullptr;
    int nStopAtHeight = gArgs.GetArg("-stopatheight", DEFAULT_STOPATHEIGHT);
    do {
        boost::this_thread::interruption_point();

        // Block until the validation queue drains. This should largely
        // never happen in normal operation, however may happen during
        // reindex, causing memory blowup if we run too far ahead.
        // Note that if a validationinterface callback ends up calling
        // ActivateBestChain this may lead to a deadlock! We should
        // probably have a DEBUG_LOCKORDER test for this in the future.
        LimitValidationInterfaceQueue();

        std::vector<uint256> connected_blocks;
        {
            LOCK2(cs_main, ::mempool.cs); // Lock transaction pool for at least as long as it takes for connectTrace to be consumed
            CBlockIndex* starting_tip = m_chain.Tip();
            bool blocks_connected = false;
            do {
                // We absolutely may not unlock cs_main until we've made forward progress
                // (with the exception of shutdown due to hardware issues, low disk space, etc).
                ConnectTrace connectTrace; // Destructed before cs_main is unlocked

                if (pindexMostWork == nullptr) {
                    pindexMostWork = FindMostWorkChain();
                }

                // Whether we have anything to do at all.
                if (pindexMostWork == nullptr || pindexMostWork == m_chain.Tip()) {
                    break;
                }

                bool fInvalidFound = false;
                std::shared_ptr<const CBlock> nullBlockPtr;
                if (!ActivateBestChainStep(state, chainparams, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullBlockPtr, fInvalidFound, connectTrace)) {
                    // A system error occurred
                    return false;
                }
                blocks_connected = true;

                if (fInvalidFound) {
                    // Wipe cache, we may need another branch now.
                    pindexMostWork = nullptr;
                }
                pindexNewTip = m_chain.Tip();

                for (const PerBlockConnectTrace& trace : connectTrace.GetBlocksConnected()) {
                    assert(trace.pblock && trace.pindex);
                    connected_blocks.push_back(trace.pblock->GetHash());
                    GetMainSignals().BlockConnected(trace.pblock, trace.pindex);
                }
            } while (!m_chain.Tip() || (starting_tip && CBlockIndexWorkComparator()(m_chain.Tip(), starting_tip)));
            if (!blocks_connected) return true;

            const CBlockIndex* pindexFork = m_chain.FindFork(starting_tip);
            bool fInitialDownload = IsInitialBlockDownload();

            // Notify external listeners about the new tip.
            // Enqueue while holding cs_main to ensure that UpdatedBlockTip is called in the order in which blocks are connected
            if (pindexFork != pindexNewTip) {
                // Notify ValidationInterface subscribers
                GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);

                // Always notify the UI if a new block tip was connected
                uiInterface.NotifyBlockTip(fInitialDownload, pindexNewTip);
            }
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        for (const auto& block_hash : connected_blocks) {
            CheckDelayedBlocks(chainparams, block_hash);
        }

        if (nStopAtHeight && pindexNewTip && pindexNewTip->nHeight >= nStopAtHeight) StartShutdown();

        // We check shutdown only after giving ActivateBestChainStep a chance to run once so that we
        // never shutdown before connecting the genesis block during LoadChainTip(). Previously this
        // caused an assert() failure during shutdown in such cases as the UTXO DB flushing checks
        // that the best block hash is non-null.
        if (ShutdownRequested())
            break;
    } while (pindexNewTip != pindexMostWork);
    CheckBlockIndex(chainparams.GetConsensus());


    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::PERIODIC)) {
        return false;
    }
    return true;
}

bool ActivateBestChain(BlockValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock) {
    return ::ChainstateActive().ActivateBestChain(state, chainparams, std::move(pblock));
}

bool CChainState::PreciousBlock(BlockValidationState& state, const CChainParams& params, CBlockIndex *pindex)
{
    {
        LOCK(cs_main);
        if (pindex->nChainWork < m_chain.Tip()->nChainWork) {
            // Nothing to do, this block is not at the tip.
            return true;
        }
        if (m_chain.Tip()->nChainWork > nLastPreciousChainwork) {
            // The chain has been extended since the last call, reset the counter.
            nBlockReverseSequenceId = -1;
        }
        nLastPreciousChainwork = m_chain.Tip()->nChainWork;
        setBlockIndexCandidates.erase(pindex);
        pindex->nSequenceId = nBlockReverseSequenceId;
        if (nBlockReverseSequenceId > std::numeric_limits<int32_t>::min()) {
            // We can't keep reducing the counter if somebody really wants to
            // call preciousblock 2**31-1 times on the same set of tips...
            nBlockReverseSequenceId--;
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && pindex->HaveTxsDownloaded()) {
            setBlockIndexCandidates.insert(pindex);
            PruneBlockIndexCandidates();
        }
    }

    return ActivateBestChain(state, params, std::shared_ptr<const CBlock>());
}
bool PreciousBlock(BlockValidationState& state, const CChainParams& params, CBlockIndex *pindex) {
    return ::ChainstateActive().PreciousBlock(state, params, pindex);
}

bool CChainState::InvalidateBlock(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex)
{
    CBlockIndex* to_mark_failed = pindex;
    bool pindex_was_in_chain = false;
    int disconnected = 0;

    // We do not allow ActivateBestChain() to run while InvalidateBlock() is
    // running, as that could cause the tip to change while we disconnect
    // blocks.
    LOCK(m_cs_chainstate);

    // We'll be acquiring and releasing cs_main below, to allow the validation
    // callbacks to run. However, we should keep the block index in a
    // consistent state as we disconnect blocks -- in particular we need to
    // add equal-work blocks to setBlockIndexCandidates as we disconnect.
    // To avoid walking the block index repeatedly in search of candidates,
    // build a map once so that we can look up candidate blocks by chain
    // work as we go.
    std::multimap<const arith_uint256, CBlockIndex *> candidate_blocks_by_work;

    {
        LOCK(cs_main);
        for (const auto& entry : m_blockman.m_block_index) {
            CBlockIndex *candidate = entry.second;
            // We don't need to put anything in our active chain into the
            // multimap, because those candidates will be found and considered
            // as we disconnect.
            // Instead, consider only non-active-chain blocks that have at
            // least as much work as where we expect the new tip to end up.
            if (!m_chain.Contains(candidate) &&
                    !CBlockIndexWorkComparator()(candidate, pindex->pprev) &&
                    candidate->IsValid(BLOCK_VALID_TRANSACTIONS) &&
                    candidate->HaveTxsDownloaded()) {
                candidate_blocks_by_work.insert(std::make_pair(candidate->nChainWork, candidate));
            }
        }
    }

    // Disconnect (descendants of) pindex, and mark them invalid.
    while (true) {
        if (ShutdownRequested()) break;

        // Make sure the queue of validation callbacks doesn't grow unboundedly.
        LimitValidationInterfaceQueue();

        LOCK(cs_main);
        LOCK(::mempool.cs); // Lock for as long as disconnectpool is in scope to make sure UpdateMempoolForReorg is called after DisconnectTip without unlocking in between
        if (!m_chain.Contains(pindex)) break;
        pindex_was_in_chain = true;
        CBlockIndex *invalid_walk_tip = m_chain.Tip();

        // ActivateBestChain considers blocks already in m_chain
        // unconditionally valid already, so force disconnect away from it.
        DisconnectedBlockTransactions disconnectpool;
        bool ret = DisconnectTip(state, chainparams, &disconnectpool);
        // DisconnectTip will add transactions to disconnectpool.
        // Adjust the mempool to be consistent with the new tip, adding
        // transactions back to the mempool if disconnecting was successful,
        // and we're not doing a very deep invalidation (in which case
        // keeping the mempool up to date is probably futile anyway).
        UpdateMempoolForReorg(disconnectpool, /* fAddToMempool = */ (++disconnected <= 10) && ret);
        if (!ret) return false;
        assert(invalid_walk_tip->pprev == m_chain.Tip());

        // We immediately mark the disconnected blocks as invalid.
        // This prevents a case where pruned nodes may fail to invalidateblock
        // and be left unable to start as they have no tip candidates (as there
        // are no blocks that meet the "have data and are not invalid per
        // nStatus" criteria for inclusion in setBlockIndexCandidates).
        invalid_walk_tip->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(invalid_walk_tip);
        setBlockIndexCandidates.erase(invalid_walk_tip);
        setBlockIndexCandidates.insert(invalid_walk_tip->pprev);
        if (invalid_walk_tip->pprev == to_mark_failed && (to_mark_failed->nStatus & BLOCK_FAILED_VALID)) {
            // We only want to mark the last disconnected block as BLOCK_FAILED_VALID; its children
            // need to be BLOCK_FAILED_CHILD instead.
            to_mark_failed->nStatus = (to_mark_failed->nStatus ^ BLOCK_FAILED_VALID) | BLOCK_FAILED_CHILD;
            setDirtyBlockIndex.insert(to_mark_failed);
        }

        // Add any equal or more work headers to setBlockIndexCandidates
        auto candidate_it = candidate_blocks_by_work.lower_bound(invalid_walk_tip->pprev->nChainWork);
        while (candidate_it != candidate_blocks_by_work.end()) {
            if (!CBlockIndexWorkComparator()(candidate_it->second, invalid_walk_tip->pprev)) {
                setBlockIndexCandidates.insert(candidate_it->second);
                candidate_it = candidate_blocks_by_work.erase(candidate_it);
            } else {
                ++candidate_it;
            }
        }

        // Track the last disconnected block, so we can correct its BLOCK_FAILED_CHILD status in future
        // iterations, or, if it's the last one, call InvalidChainFound on it.
        to_mark_failed = invalid_walk_tip;
    }

    CheckBlockIndex(chainparams.GetConsensus());

    {
        LOCK(cs_main);
        if (m_chain.Contains(to_mark_failed)) {
            // If the to-be-marked invalid block is in the active chain, something is interfering and we can't proceed.
            return false;
        }

        // Mark pindex (or the last disconnected block) as invalid, even when it never was in the main chain
        to_mark_failed->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(to_mark_failed);
        setBlockIndexCandidates.erase(to_mark_failed);
        m_blockman.m_failed_blocks.insert(to_mark_failed);

        // If any new blocks somehow arrived while we were disconnecting
        // (above), then the pre-calculation of what should go into
        // setBlockIndexCandidates may have missed entries. This would
        // technically be an inconsistency in the block index, but if we clean
        // it up here, this should be an essentially unobservable error.
        // Loop back over all block index entries and add any missing entries
        // to setBlockIndexCandidates.
        BlockMap::iterator it = m_blockman.m_block_index.begin();
        while (it != m_blockman.m_block_index.end()) {
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->HaveTxsDownloaded() && !setBlockIndexCandidates.value_comp()(it->second, m_chain.Tip())) {
                setBlockIndexCandidates.insert(it->second);
            }
            it++;
        }

        InvalidChainFound(to_mark_failed);
    }

    // Only notify about a new block tip if the active chain was modified.
    if (pindex_was_in_chain) {
        uiInterface.NotifyBlockTip(IsInitialBlockDownload(), to_mark_failed->pprev);
    }
    return true;
}

bool InvalidateBlock(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex) {
    return ::ChainstateActive().InvalidateBlock(state, chainparams, pindex);
}

void CChainState::ResetBlockFailureFlags(CBlockIndex *pindex) {
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = m_blockman.m_block_index.begin();
    while (it != m_blockman.m_block_index.end()) {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex) {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            it->second->nFlags &= ~(BLOCK_FAILED_DUPLICATE_STAKE | BLOCK_STAKE_KERNEL_SPENT);
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->HaveTxsDownloaded() && setBlockIndexCandidates.value_comp()(m_chain.Tip(), it->second)) {
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid) {
                // Reset invalid block marker if it was pointing to one of those.
                pindexBestInvalid = nullptr;
            }
            m_blockman.m_failed_blocks.erase(it->second);
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != nullptr) {
        if (pindex->nStatus & BLOCK_FAILED_MASK) {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pindex);
            m_blockman.m_failed_blocks.erase(pindex);
        }
        pindex = pindex->pprev;
    }
}

void ResetBlockFailureFlags(CBlockIndex *pindex) {
    return ::ChainstateActive().ResetBlockFailureFlags(pindex);
}

CBlockIndex* BlockManager::AddToBlockIndex(const CBlockHeader& block)
{
    AssertLockHeld(cs_main);

    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator it = m_block_index.find(hash);
    if (it != m_block_index.end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(block);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator mi = m_block_index.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = m_block_index.find(block.hashPrevBlock);
    if (miPrev != m_block_index.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nTimeMax = (pindexNew->pprev ? std::max(pindexNew->pprev->nTimeMax, pindexNew->nTime) : pindexNew->nTime);
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);

    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pindexBestHeader == nullptr || pindexBestHeader->nChainWork < pindexNew->nChainWork)
        pindexBestHeader = pindexNew;

    setDirtyBlockIndex.insert(pindexNew);

    return pindexNew;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
void CChainState::ReceivedBlockTransactions(const CBlock& block, CBlockIndex* pindexNew, const FlatFilePos& pos, const Consensus::Params& consensusParams)
{
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    if (IsWitnessEnabled(pindexNew->pprev, consensusParams)) {
        pindexNew->nStatus |= BLOCK_OPT_WITNESS;
    }
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    if (pindexNew->pprev == nullptr || pindexNew->pprev->HaveTxsDownloaded()) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            {
                LOCK(cs_nBlockSequenceId);
                pindex->nSequenceId = nBlockSequenceId++;
            }
            if (m_chain.Tip() == nullptr || !setBlockIndexCandidates.value_comp()(pindex, m_chain.Tip())) {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = m_blockman.m_blocks_unlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                m_blockman.m_blocks_unlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            m_blockman.m_blocks_unlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }
}

static bool FindBlockPos(FlatFilePos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        bool out_of_space;
        size_t bytes_allocated = BlockFileSeq().Allocate(pos, nAddSize, out_of_space);
        if (out_of_space) {
            return AbortNode("Disk space is too low!", _("Error: Disk space is too low!").translated, CClientUIInterface::MSG_NOPREFIX);
        }
        if (bytes_allocated != 0 && fPruneMode) {
            fCheckForPruning = true;
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

static bool FindUndoPos(BlockValidationState &state, int nFile, FlatFilePos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    bool out_of_space;
    size_t bytes_allocated = UndoFileSeq().Allocate(pos, nAddSize, out_of_space);
    if (out_of_space) {
        return AbortNode(state, "Disk space is too low!", _("Error: Disk space is too low!").translated, CClientUIInterface::MSG_NOPREFIX);
    }
    if (bytes_allocated != 0 && fPruneMode) {
        fCheckForPruning = true;
    }

    return true;
}

static bool CheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true)
{
    if (fGhostMode
        && !block.IsGhostVersion())
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "block-version", "bad block version");

    // Check timestamp
    if (fGhostMode
        && !block.hashPrevBlock.IsNull() // allow genesis block to be created in the future
        && block.GetBlockTime() > FutureDrift(GetAdjustedTime()))
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "block-timestamp", "block timestamp too far in the future");

    // Check proof of work matches claimed amount
    if (!fGhostMode
        && fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "high-hash", "proof of work failed");

    return true;
}


bool CheckBlockSignature(const CBlock &block)
{
    if (!block.IsProofOfStake())
        return block.vchBlockSig.empty();
    if (block.vchBlockSig.empty())
        return false;
    if (block.vtx[0]->vin.size() < 1)
        return false;

    const auto &txin = block.vtx[0]->vin[0];
    if (txin.scriptWitness.stack.size() != 2)
        return false;

    if (txin.scriptWitness.stack[1].size() != 33)
        return false;

    CPubKey pubKey(txin.scriptWitness.stack[1]);
    return pubKey.Verify(block.GetHash(), block.vchBlockSig);
};

bool AddToMapStakeSeen(const COutPoint &kernel, const uint256 &blockHash)
{
    // Overwrites existing values

    std::pair<std::map<COutPoint, uint256>::iterator,bool> ret;
    ret = mapStakeSeen.insert(std::pair<COutPoint, uint256>(kernel, blockHash));
    if (ret.second == false) { // existing element
        ret.first->second = blockHash;
    } else {
        listStakeSeen.push_back(kernel);
    }

    return true;
};

bool CheckStakeUnused(const COutPoint &kernel)
{
    std::map<COutPoint, uint256>::const_iterator mi = mapStakeSeen.find(kernel);
    return (mi == mapStakeSeen.end());
}

bool CheckStakeUnique(const CBlock &block, bool fUpdate)
{
    LOCK(cs_main);

    uint256 blockHash = block.GetHash();
    const COutPoint &kernel = block.vtx[0]->vin[0].prevout;

    std::map<COutPoint, uint256>::const_iterator mi = mapStakeSeen.find(kernel);
    if (mi != mapStakeSeen.end()) {
        if (mi->second == blockHash) {
            return true;
        }
        return error("%s: Stake kernel for %s first seen on %s.", __func__, blockHash.ToString(), mi->second.ToString());
    }

    if (!fUpdate) {
        return true;
    }

    while (listStakeSeen.size() > MAX_STAKE_SEEN_SIZE) {
        const COutPoint &oldest = listStakeSeen.front();
        if (1 != mapStakeSeen.erase(oldest)) {
            LogPrintf("%s: Warning: mapStakeSeen did not erase %s %n\n", __func__, oldest.hash.ToString(), oldest.n);
        }
        listStakeSeen.pop_front();
    }

    return AddToMapStakeSeen(kernel, blockHash);
};

bool CheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, fCheckPOW))
        return false;

    state.SetStateInfo(block.nTime, -1, consensusParams, fGhostMode, (fBusyImporting && fSkipRangeproof));

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;

        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);

        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-txnmrklroot", "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-txns-duplicate", "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");

    if (fGhostMode) {
        if (!::ChainstateActive().IsInitialBlockDownload()
            && block.vtx[0]->IsCoinStake()
            && !CheckStakeUnique(block)) {
            //state.DoS(10, false, "bad-cs-duplicate", false, "duplicate coinstake");

            state.nFlags |= BLOCK_FAILED_DUPLICATE_STAKE;

            /*
            // TODO: ask peers which stake kernel they have
            if (chainActive.Tip()->nHeight < GetNumBlocksOfPeers() - 8) // peers have significantly longer chain, this node must've got the wrong stake 1st
            {
                LogPrint(BCLog::POS, "%s: Ignoring CheckStakeUnique for block %s, chain height behind peers.\n", __func__, block.GetHash().ToString());
                const COutPoint &kernel = block.vtx[0]->vin[0].prevout;
                mapStakeSeen[kernel] = block.GetHash();
            } else
                return state.DoS(20, false, "bad-cs-duplicate", false, "duplicate coinstake");
            */
        }

        // First transaction must be coinbase (genesis only) or coinstake
        // 2nd txn may be coinbase in early blocks: check further in ContextualCheckBlock
        if (!(block.vtx[0]->IsCoinBase() || block.vtx[0]->IsCoinStake())) { // only genesis can be coinbase, check in ContextualCheckBlock
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-missing", "first tx is not coinbase");
        }

        // 2nd txn may never be coinstake, remaining txns must not be coinbase/stake
        for (size_t i = 1; i < block.vtx.size(); i++) {
            if ((i > 1 && block.vtx[i]->IsCoinBase()) || block.vtx[i]->IsCoinStake()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-multiple", "more than one coinbase or coinstake");
            }
        }

        if (!CheckBlockSignature(block)) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-block-signature", "bad block signature");
        }
    } else {
        // First transaction must be coinbase, the rest must not be
        if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-missing", "first tx is not coinbase");
        for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-multiple", "more than one coinbase");
    }

    // Check transactions
    // Must check for duplicate inputs (see CVE-2018-17144)
    for (const auto& tx : block.vtx) {
        TxValidationState tx_state;
        tx_state.SetStateInfo(block.nTime, -1, consensusParams, fGhostMode, (fBusyImporting && fSkipRangeproof));
        if (!CheckTransaction(*tx, tx_state)) {
            // CheckBlock() does context-free validation checks. The only
            // possible failures are consensus failures.
            assert(tx_state.GetResult() == TxValidationResult::TX_CONSENSUS);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, tx_state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), tx_state.GetDebugMessage()));
        }
    }
    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops", "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

bool IsWitnessEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    if (fGhostMode) return true;

    int height = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;
    return (height >= params.SegwitHeight);
}

int GetWitnessCommitmentIndex(const CBlock& block)
{
    int commitpos = -1;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            const CTxOut& vout = block.vtx[0]->vout[o];
            if (vout.scriptPubKey.size() >= MINIMUM_WITNESS_COMMITMENT &&
                vout.scriptPubKey[0] == OP_RETURN &&
                vout.scriptPubKey[1] == 0x24 &&
                vout.scriptPubKey[2] == 0xaa &&
                vout.scriptPubKey[3] == 0x21 &&
                vout.scriptPubKey[4] == 0xa9 &&
                vout.scriptPubKey[5] == 0xed) {
                commitpos = o;
            }
        }
    }
    return commitpos;
}

void UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != -1 && IsWitnessEnabled(pindexPrev, consensusParams) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}

std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    std::vector<unsigned char> commitment;
    if (fGhostMode) {
        return commitment;
    }

    int commitpos = GetWitnessCommitmentIndex(block);
    std::vector<unsigned char> ret(32, 0x00);
    if (consensusParams.SegwitHeight != std::numeric_limits<int>::max()) {
        if (commitpos == -1) {
            uint256 witnessroot = BlockWitnessMerkleRoot(block, nullptr);
            CHash256().Write(witnessroot.begin(), 32).Write(ret.data(), 32).Finalize(witnessroot.begin());
            CTxOut out;
            out.nValue = 0;
            out.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
            out.scriptPubKey[0] = OP_RETURN;
            out.scriptPubKey[1] = 0x24;
            out.scriptPubKey[2] = 0xaa;
            out.scriptPubKey[3] = 0x21;
            out.scriptPubKey[4] = 0xa9;
            out.scriptPubKey[5] = 0xed;
            memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
            commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
            CMutableTransaction tx(*block.vtx[0]);
            tx.vout.push_back(out);
            block.vtx[0] = MakeTransactionRef(std::move(tx));
        }
    }
    UpdateUncommittedBlockStructures(block, pindexPrev, consensusParams);
    return commitment;
}

unsigned int GetNextTargetRequired(const CBlockIndex *pindexLast)
{
    const Consensus::Params &consensus = Params().GetConsensus();

    arith_uint256 bnProofOfWorkLimit;
    unsigned int nProofOfWorkLimit;
    int nHeight = pindexLast ? pindexLast->nHeight+1 : 0;

    if (nHeight < (int)Params().GetLastImportHeight()) {
        if (nHeight == 0) {
            return arith_uint256("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").GetCompact();
        }
        int nLastImportHeight = (int) Params().GetLastImportHeight();
        arith_uint256 nMaxProofOfWorkLimit = arith_uint256("000000000008ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        arith_uint256 nMinProofOfWorkLimit = UintToArith256(consensus.powLimit);
        arith_uint256 nStep = (nMaxProofOfWorkLimit - nMinProofOfWorkLimit) / nLastImportHeight;

        bnProofOfWorkLimit = nMaxProofOfWorkLimit - (nStep * nHeight);
        nProofOfWorkLimit = bnProofOfWorkLimit.GetCompact();
    } else {
        bnProofOfWorkLimit = UintToArith256(consensus.powLimit);
        nProofOfWorkLimit = bnProofOfWorkLimit.GetCompact();
    }

    if (pindexLast == nullptr)
        return nProofOfWorkLimit; // Genesis block

    const CBlockIndex* pindexPrev = pindexLast;
    if (pindexPrev->pprev == nullptr)
        return nProofOfWorkLimit; // first block
    const CBlockIndex *pindexPrevPrev = pindexPrev->pprev;
    if (pindexPrevPrev->pprev == nullptr)
        return nProofOfWorkLimit; // second block

    int64_t nTargetSpacing = Params().GetTargetSpacing();
    int64_t nTargetTimespan = Params().GetTargetTimespan();
    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    if (nActualSpacing > nTargetSpacing * 10)
        nActualSpacing = nTargetSpacing * 10;

    // pos: target change every block
    // pos: retarget with exponential moving toward target spacing
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    int64_t nInterval = nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    if (bnNew <= 0 || bnNew > bnProofOfWorkLimit)
        return nProofOfWorkLimit;

    return bnNew.GetCompact();
}

/** Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock().
 *  NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const CChainParams& params, const CBlockIndex* pindexPrev, int64_t nAdjustedTime) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;
    const Consensus::Params& consensusParams = params.GetConsensus();

    if (fGhostMode && pindexPrev) {
        // Check proof-of-stake
        if (block.nBits != GetNextTargetRequired(pindexPrev))
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-diffbits-pos", "incorrect proof of stake");
    } else {
        // Check proof of work
        if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-diffbits", "incorrect proof of work");
    }

    // Check against checkpoints
    if (fCheckpointsEnabled) {
        // Don't accept any forks from the main chain prior to last checkpoint.
        // GetLastCheckpoint finds the last checkpoint in MapCheckpoints that's in our
        // BlockIndex().
        CBlockIndex* pcheckpoint = GetLastCheckpoint(params.Checkpoints());
        if (pcheckpoint && nHeight < pcheckpoint->nHeight) {
            LogPrintf("ERROR: %s: forked chain older than last checkpoint (height %d)\n", __func__, nHeight);
            return state.Invalid(BlockValidationResult::BLOCK_CHECKPOINT, "bad-fork-prior-to-checkpoint");
        }
    }

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "time-too-old", "block's timestamp is too early");

    // Check timestamp
    if (nHeight > 0
        && block.GetBlockTime() > nAdjustedTime + MAX_FUTURE_BLOCK_TIME)
        return state.Invalid(BlockValidationResult::BLOCK_TIME_FUTURE, "time-too-new", "block timestamp too far in the future");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    // check for version 2, 3 and 4 upgrades
    if((block.nVersion < 2 && nHeight >= consensusParams.BIP34Height) ||
       (block.nVersion < 3 && nHeight >= consensusParams.BIP66Height) ||
       (block.nVersion < 4 && nHeight >= consensusParams.BIP65Height))
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));

    return true;
}

/** NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev, bool accept_block=false) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;
    const int64_t nPrevTime = pindexPrev ? pindexPrev->nTime : 0;

    // Start enforcing BIP113 (Median Time Past).
    int nLockTimeFlags = 0;
    if ((fGhostMode && pindexPrev) || nHeight >= consensusParams.CSVHeight) {
        assert(pindexPrev != nullptr);
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

    int64_t nLockTimeCutoff = (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                              ? (pindexPrev ? pindexPrev->GetMedianTimePast() : block.GetBlockTime())
                              : block.GetBlockTime();

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal", "non-final transaction");
        }
    }

    if (fGhostMode) {
        // Enforce rule that the coinbase/coinstake ends with serialized block height
        // genesis block scriptSig size will be different

        if (block.IsProofOfStake()) {
            // Limit the number of outputs in a coinstake txn to 6: 1 data + 1 foundation + 4 user
            if (nPrevTime >= consensusParams.OpIsCoinstakeTime) {
                if (block.vtx[0]->vpout.size() > 6) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-outputs", "Too many outputs in coinstake");
                }
            }

            // coinstake output 0 must be data output of blockheight
            int i;
            if (!block.vtx[0]->GetCoinStakeHeight(i)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-malformed", "coinstake txn is malformed");
            }

            if (i != nHeight) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-height", "block height mismatch in coinstake");
            }

            std::vector<uint8_t> &vData = ((CTxOutData*)block.vtx[0]->vpout[0].get())->vData;
            if (vData.size() > 8 && vData[4] == DO_VOTE) {
                uint32_t voteToken;
                memcpy(&voteToken, &vData[5], 4);

                LogPrint(BCLog::HDWALLET, _("Block %d casts vote for option %u of proposal %u.\n").translated.c_str(),
                    nHeight, voteToken >> 16, voteToken & 0xFFFF);
            }

            // check witness merkleroot, TODO: should witnessmerkleroot be hashed?
            bool malleated = false;
            uint256 hashWitness = BlockWitnessMerkleRoot(block, &malleated);

            if (hashWitness != block.hashWitnessMerkleRoot) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-witness-merkle-match", strprintf("%s : witness merkle commitment mismatch", __func__));
            }

            if (!CheckCoinStakeTimestamp(nHeight, block.GetBlockTime())) {
                return state.Invalid(BlockValidationResult::DOS_50, "bad-coinstake-time", strprintf("%s: coinstake timestamp violation nTimeBlock=%d", __func__, block.GetBlockTime()));
            }

            // Check timestamp against prev
            if (block.GetBlockTime() <= pindexPrev->GetPastTimeLimit() || FutureDrift(block.GetBlockTime()) < pindexPrev->GetBlockTime()) {
                return state.Invalid(BlockValidationResult::DOS_50, "bad-block-time", strprintf("%s: block's timestamp is too early", __func__));
            }

            uint256 hashProof, targetProofOfStake;

            // Blocks are connected at end of import / reindex
            // CheckProofOfStake is run again during connectblock
            if (!::ChainstateActive().IsInitialBlockDownload() // checks (!fImporting && !fReindex)
                && (!accept_block || ::ChainActive().Height() > (int)Params().GetStakeMinConfirmations())
                && !CheckProofOfStake(state, pindexPrev, *block.vtx[0], block.nTime, block.nBits, hashProof, targetProofOfStake)) {
                return error("ContextualCheckBlock(): check proof-of-stake failed for block %s\n", block.GetHash().ToString());
            }
        } else {
            bool fCheckPOW = true; // TODO: pass properly
            if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams, nHeight, Params().GetLastImportHeight()))
                return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "high-hash", "proof of work failed");

            // Enforce rule that the coinbase/ ends with serialized block height
            // genesis block scriptSig size will be different
            CScript expect = CScript() << OP_RETURN << nHeight;
            const CScript &scriptSig = block.vtx[0]->vin[0].scriptSig;
            if (scriptSig.size() < expect.size() ||
                !std::equal(expect.begin()
                    , expect.end(), scriptSig.begin() + scriptSig.size()-expect.size())) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-height", "block height mismatch in coinbase");
            }
        }

        if (nHeight > 0 && !block.vtx[0]->IsCoinStake()) { // only genesis block can start with coinbase
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-missing", "first tx is not coinstake");
        }

        if (nHeight > 0 // skip genesis
            && Params().GetLastImportHeight() >= (uint32_t)nHeight) {
            // 2nd txn must be coinbase
            if (block.vtx.size() < 2 || !block.vtx[1]->IsCoinBase()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb", "Second txn of import block must be coinbase");
            }

            // Check hash of genesis import txn matches expected hash.
            uint256 txnHash = block.vtx[1]->GetHash();
            if (!Params().CheckImportCoinbase(nHeight, txnHash)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb", "Incorrect outputs hash.");
            }
        } else {
            // 2nd txn can't be coinbase if block height > GetLastImportHeight
            if (block.vtx.size() > 1 && block.vtx[1]->IsCoinBase()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-multiple", "unexpected coinbase");
            }
        }
    } else {
        if (nHeight >= consensusParams.BIP34Height)
        {
            CScript expect = CScript() << nHeight;
            if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
                !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-height", "block height mismatch in coinbase");
            }
        }

        // Validation for witness commitments.
        // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
        //   coinbase (where 0x0000....0000 is used instead).
        // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness reserved value (unconstrained).
        // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
        // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
        //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness reserved value). In case there are
        //   multiple, the last one is used.
        bool fHaveWitness = false;
        if (nHeight >= consensusParams.SegwitHeight) {
            int commitpos = GetWitnessCommitmentIndex(block);
            if (commitpos != -1) {
                bool malleated = false;
                uint256 hashWitness = BlockWitnessMerkleRoot(block, &malleated);
                // The malleation check is ignored; as the transaction tree itself
                // already does not permit it, it is impossible to trigger in the
                // witness tree.
                if (block.vtx[0]->vin[0].scriptWitness.stack.size() != 1 || block.vtx[0]->vin[0].scriptWitness.stack[0].size() != 32) {
                    return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-witness-nonce-size", strprintf("%s : invalid witness reserved value size", __func__));
                }
                CHash256().Write(hashWitness.begin(), 32).Write(&block.vtx[0]->vin[0].scriptWitness.stack[0][0], 32).Finalize(hashWitness.begin());
                if (memcmp(hashWitness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                    return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-witness-merkle-match", strprintf("%s : witness merkle commitment mismatch", __func__));
                }
                fHaveWitness = true;
            }
        }

        // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
        if (!fHaveWitness) {
          for (const auto& tx : block.vtx) {
                if (tx->HasWitness()) {
                    return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "unexpected-witness", strprintf("%s : unexpected witness data found", __func__));
                }
            }
        }
    }

    // After the coinbase witness reserved value and commitment are verified,
    // we can check if the block weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the block hash, so we couldn't mark the block as permanently
    // failed).
    if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-weight", strprintf("%s : weight limit failed", __func__));
    }

    return true;
}

bool ProcessDuplicateStakeHeader(CBlockIndex *pindex, NodeId nodeId) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!pindex) {
        return false;
    }

    uint256 hash = pindex->GetBlockHash();

    bool fMakeValid = false;
    if (nodeId == -1) {
        LogPrintf("%s: Duplicate stake block %s was received in a group, marking valid.\n",
            __func__, hash.ToString());

        fMakeValid = true;
    }

    if (nodeId > -1) {
        std::pair<std::map<uint256, StakeConflict>::iterator,bool> ret;
        ret = mapStakeConflict.insert(std::pair<uint256, StakeConflict>(hash, StakeConflict()));
        StakeConflict &sc = ret.first->second;
        sc.Add(nodeId);

        if ((int)sc.peerCount.size() > std::min(GetNumPeers() / 2, 4)) {
            LogPrintf("%s: More than half the connected peers are building on block %s," /* Continued */
                "  marked as duplicate stake, assuming this node has the duplicate.\n", __func__, hash.ToString());

            fMakeValid = true;
        }
    }

    if (fMakeValid) {
        pindex->nFlags &= (~BLOCK_FAILED_DUPLICATE_STAKE);
        pindex->nStatus &= (~BLOCK_FAILED_VALID);
        setDirtyBlockIndex.insert(pindex);

        //if (pindex->nStatus & BLOCK_FAILED_CHILD)
        //{
            CBlockIndex *pindexPrev = pindex->pprev;
            while (pindexPrev) {
                if (pindexPrev->nStatus & BLOCK_VALID_MASK) {
                    break;
                }

                if (pindexPrev->nFlags & BLOCK_FAILED_DUPLICATE_STAKE) {
                    pindexPrev->nFlags &= (~BLOCK_FAILED_DUPLICATE_STAKE);
                    pindexPrev->nStatus &= (~BLOCK_FAILED_VALID);
                    setDirtyBlockIndex.insert(pindexPrev);

                    if (!pindexPrev->prevoutStake.IsNull()) {
                        uint256 prevhash = pindexPrev->GetBlockHash();
                        AddToMapStakeSeen(pindexPrev->prevoutStake, prevhash);
                    }

                    pindexPrev->nStatus &= (~BLOCK_FAILED_CHILD);
                }

                pindexPrev = pindexPrev->pprev;
            }

            pindex->nStatus &= (~BLOCK_FAILED_CHILD);
        //};

        if (!pindex->prevoutStake.IsNull()) {
            AddToMapStakeSeen(pindex->prevoutStake, hash);
        }
        return true;
    }

    return false;
}

size_t MAX_DELAYED_BLOCKS = 64;
int64_t MAX_DELAY_BLOCK_SECONDS = 180;

class DelayedBlock
{
public:
    DelayedBlock(const std::shared_ptr<const CBlock>& pblock, int node_id) : m_pblock(pblock), m_node_id(node_id) {
        m_time = GetTime();
    }
    int64_t m_time;
    std::shared_ptr<const CBlock> m_pblock;
    int m_node_id;
};
std::list<DelayedBlock> list_delayed_blocks;

extern void Misbehaving(NodeId nodeid, int howmuch, const std::string& message="") EXCLUSIVE_LOCKS_REQUIRED(cs_main);
extern void IncPersistentMisbehaviour(NodeId node_id, int howmuch) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
extern bool AddNodeHeader(NodeId node_id, const uint256 &hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
extern void RemoveNodeHeader(const uint256 &hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
extern void RemoveNonReceivedHeaderFromNodes(BlockMap::iterator mi) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
extern bool IncDuplicateHeaders(NodeId node_id) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

void EraseDelayedBlock(std::list<DelayedBlock>::iterator p) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (p->m_node_id > -1) {
        Misbehaving(p->m_node_id, 25, "Delayed block");
    }

    auto it = ::BlockIndex().find(p->m_pblock->GetHash());
    if (it != ::BlockIndex().end()) {
        it->second->nFlags &= ~BLOCK_DELAYED;
        setDirtyBlockIndex.insert(it->second);
    }
}

extern NodeId GetBlockSource(uint256 hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool DelayBlock(const std::shared_ptr<const CBlock>& pblock, BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    NodeId nodeId = GetBlockSource(pblock->GetHash());
    LogPrintf("Warning: %s - Previous stake modifier is null for block %s from peer %d.\n", __func__, pblock->GetHash().ToString(), nodeId);
    while (list_delayed_blocks.size() >= MAX_DELAYED_BLOCKS) {
        LogPrint(BCLog::NET, "Removing Delayed block %s, too many delayed.\n", pblock->GetHash().ToString());
        EraseDelayedBlock(list_delayed_blocks.begin());
        list_delayed_blocks.erase(list_delayed_blocks.begin());
    }
    assert(list_delayed_blocks.size() < MAX_DELAYED_BLOCKS);
    state.nFlags |= BLOCK_DELAYED; // Mark to prevent further processing
    list_delayed_blocks.emplace_back(pblock, nodeId);
    return true;
}

void CheckDelayedBlocks(const CChainParams& chainparams, const uint256 &block_hash) LOCKS_EXCLUDED(cs_main)
{
    if (list_delayed_blocks.empty()) {
        return;
    }

    int64_t now = GetTime();
    std::vector<std::shared_ptr<const CBlock> > process_blocks;
    {
        LOCK(cs_main);
        std::list<DelayedBlock>::iterator p = list_delayed_blocks.begin();
        while (p != list_delayed_blocks.end()) {
            if (p->m_pblock->hashPrevBlock == block_hash) {
                process_blocks.push_back(p->m_pblock);
                p = list_delayed_blocks.erase(p);
                continue;
            }
            if (p->m_time + MAX_DELAY_BLOCK_SECONDS < now) {
                LogPrint(BCLog::NET, "Removing delayed block %s, timed out.\n", p->m_pblock->GetHash().ToString());
                EraseDelayedBlock(p);
                p = list_delayed_blocks.erase(p);
                continue;
            }
            ++p;
        }
    }

    for (auto &p : process_blocks) {
        LogPrint(BCLog::NET, "Processing delayed block %s prev %s.\n", p->GetHash().ToString(), block_hash.ToString());
        ProcessNewBlock(chainparams, p, false, nullptr); // Should update DoS if necessary, finding block through mapBlockSource
    }
}

bool RemoveUnreceivedHeader(const uint256 &hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    BlockMap::iterator mi = ::BlockIndex().find(hash);
    if (mi != ::BlockIndex().end() && (mi->second->nFlags & BLOCK_ACCEPTED)) {
        return false;
    }
    if (mi == ::BlockIndex().end()) {
        return true; // was already removed, peer misbehaving
    }

    // Remove entire chain
    std::vector<BlockMap::iterator> remove_headers;
    std::vector<BlockMap::iterator> last_round[2];

    size_t n = 0;
    last_round[n].push_back(mi);
    remove_headers.push_back(mi);
    while (last_round[n].size()) {
        last_round[!n].clear();

        for (BlockMap::iterator& check_header : last_round[n]) {
            BlockMap::iterator it = ::BlockIndex().begin();
            while (it != ::BlockIndex().end()) {
                if (it->second->pprev == check_header->second) {
                    if ((it->second->nFlags & BLOCK_ACCEPTED)) {
                        LogPrintf("Can't remove header %s, descendant block %s accepted.\n", hash.ToString(), it->second->GetBlockHash().ToString());
                        return true; // Can't remove any blocks, peer misbehaving for not sending
                    }
                    last_round[!n].push_back(it);
                    remove_headers.push_back(it);
                }
                it++;
            }
        }
        n = !n;
    }

    LogPrintf("Removing %d loose headers from %s.\n", remove_headers.size(), hash.ToString());

    for (auto &entry : remove_headers) {
        LogPrint(BCLog::NET, "Removing loose header %s.\n", entry->second->GetBlockHash().ToString());
        setDirtyBlockIndex.erase(entry->second);

        if (pindexBestHeader == entry->second) {
            pindexBestHeader = ::ChainActive().Tip();
        }
        if (pindexBestInvalid == entry->second) {
            pindexBestInvalid = nullptr;
        }
        RemoveNonReceivedHeaderFromNodes(entry);
        delete entry->second;
        ::BlockIndex().erase(entry);
    }

    return true;
}

size_t CountDelayedBlocks() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    return list_delayed_blocks.size();
}

CoinStakeCache smsgFeeCoinstakeCache;
int64_t GetSmsgFeeRate(const CBlockIndex *pindex, bool reduce_height) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const Consensus::Params &consensusParams = Params().GetConsensus();
    int64_t smsg_fee_rate = consensusParams.smsg_fee_msg_per_day_per_k;

    if ((pindex && pindex->nTime < consensusParams.smsg_fee_time)
        || (!pindex && GetTime() < consensusParams.smsg_fee_time)) {
        return smsg_fee_rate;
    }

    int chain_height = pindex ? pindex->nHeight : ::ChainActive().Height();
    if (reduce_height) { // Grace period, push back to previous period
        chain_height -= 10;
    }
    int fee_height = (chain_height / consensusParams.smsg_fee_period) * consensusParams.smsg_fee_period;

    CBlockIndex *fee_block = ::ChainActive()[fee_height];
    if (!fee_block || fee_block->nTime < consensusParams.smsg_fee_time) {
        return smsg_fee_rate;
    }

    CTransactionRef coinstake = nullptr;
    if (!smsgFeeCoinstakeCache.GetCoinStake(fee_block->GetBlockHash(), coinstake)
        || !coinstake->GetSmsgFeeRate(smsg_fee_rate)) {
        return smsg_fee_rate;
    }

    return smsg_fee_rate;
};

CoinStakeCache smsgDifficultyCoinstakeCache(180);
uint32_t GetSmsgDifficulty(uint64_t time, bool verify) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const Consensus::Params &consensusParams = Params().GetConsensus();
    uint32_t smsg_difficulty = consensusParams.smsg_min_difficulty;

    CBlockIndex *pindex = ::ChainActive().Tip();
    for (size_t k = 0; k < 180; ++k) {
        if (!pindex) {
            break;
        }
        if (time >= pindex->nTime) {
            CTransactionRef coinstake = nullptr;
            if (smsgDifficultyCoinstakeCache.GetCoinStake(pindex->GetBlockHash(), coinstake)
                && coinstake->GetSmsgDifficulty(smsg_difficulty)) {
                    break;
            }
        }
        pindex = pindex->pprev;
    }

    if (verify && smsg_difficulty != consensusParams.smsg_min_difficulty) {
        return smsg_difficulty + consensusParams.smsg_difficulty_max_delta;
    }
    return smsg_difficulty - consensusParams.smsg_difficulty_max_delta;
};

bool BlockManager::AcceptBlockHeader(const CBlockHeader& block, BlockValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator miSelf = m_block_index.find(hash);
    CBlockIndex *pindex = nullptr;
    if (hash != chainparams.GetConsensus().hashGenesisBlock) {
        if (miSelf != m_block_index.end()) {
            // Block header is already known.
            if (fGhostMode && !fRequested && !::ChainstateActive().IsInitialBlockDownload() && state.nodeId >= 0
                && !IncDuplicateHeaders(state.nodeId)) {
                Misbehaving(state.nodeId, 5, "Too many duplicates");
            }

            pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                LogPrintf("ERROR: %s: block %s is marked invalid\n", __func__, hash.ToString());
                return state.Invalid(BlockValidationResult::BLOCK_CACHED_INVALID, "duplicate");
            }
            return true;
        }

        if (!CheckBlockHeader(block, state, chainparams.GetConsensus()))
            return error("%s: Consensus::CheckBlockHeader: %s, %s", __func__, hash.ToString(), state.ToString());

        // Get prev block index
        CBlockIndex* pindexPrev = nullptr;
        BlockMap::iterator mi = m_block_index.find(block.hashPrevBlock);
        if (mi == m_block_index.end()) {
            LogPrintf("ERROR: %s: prev block not found\n", __func__);
            return state.Invalid(BlockValidationResult::BLOCK_MISSING_PREV, "prev-blk-not-found");
        }
        pindexPrev = (*mi).second;
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK) {
            LogPrintf("ERROR: %s: prev block invalid\n", __func__);
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
        }
        if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev, GetAdjustedTime()))
            return error("%s: Consensus::ContextualCheckBlockHeader: %s, %s", __func__, hash.ToString(), state.ToString());

        /* Determine if this block descends from any block which has been found
         * invalid (m_failed_blocks), then mark pindexPrev and any blocks between
         * them as failed. For example:
         *
         *                D3
         *              /
         *      B2 - C2
         *    /         \
         *  A             D2 - E2 - F2
         *    \
         *      B1 - C1 - D1 - E1
         *
         * In the case that we attempted to reorg from E1 to F2, only to find
         * C2 to be invalid, we would mark D2, E2, and F2 as BLOCK_FAILED_CHILD
         * but NOT D3 (it was not in any of our candidate sets at the time).
         *
         * In any case D3 will also be marked as BLOCK_FAILED_CHILD at restart
         * in LoadBlockIndex.
         */
        if (!pindexPrev->IsValid(BLOCK_VALID_SCRIPTS)) {
            // The above does not mean "invalid": it checks if the previous block
            // hasn't been validated up to BLOCK_VALID_SCRIPTS. This is a performance
            // optimization, in the common case of adding a new block to the tip,
            // we don't need to iterate over the failed blocks list.
            for (const CBlockIndex* failedit : m_failed_blocks) {
                if (pindexPrev->GetAncestor(failedit->nHeight) == failedit) {
                    //assert(failedit->nStatus & BLOCK_FAILED_VALID);
                    CBlockIndex* invalid_walk = pindexPrev;
                    if (failedit->nStatus & BLOCK_FAILED_VALID)
                    while (invalid_walk != failedit) {
                        invalid_walk->nStatus |= BLOCK_FAILED_CHILD;
                        setDirtyBlockIndex.insert(invalid_walk);
                        invalid_walk = invalid_walk->pprev;
                    }
                    LogPrintf("ERROR: %s: prev block invalid\n", __func__);
                    return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
                }
            }
        }
    }
    if (pindex == nullptr) {
        bool force_accept = true;
        if (fGhostMode && !::ChainstateActive().IsInitialBlockDownload() && state.nodeId >= 0) {
            if (!AddNodeHeader(state.nodeId, hash)) {
                LogPrintf("ERROR: %s: DoS limits\n", __func__);
                return state.Invalid(BlockValidationResult::DOS_20, "dos-limits");
            }
            force_accept = false;
        }
        pindex = AddToBlockIndex(block);
        if (force_accept) {
            pindex->nFlags |= BLOCK_ACCEPTED;
        }
    }

    if (ppindex)
        *ppindex = pindex;

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& headers, BlockValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex)
{
    {
        LOCK(cs_main);
        for (const CBlockHeader& header : headers) {
            CBlockIndex *pindex = nullptr; // Use a temp pindex instead of ppindex to avoid a const_cast
            bool accepted = g_chainman.m_blockman.AcceptBlockHeader(
                header, state, chainparams, &pindex);
            ::ChainstateActive().CheckBlockIndex(chainparams.GetConsensus());

            if (!accepted) {
                return false;
            }
            if (ppindex) {
                *ppindex = pindex;
            }
        }
    }
    if (NotifyHeaderTip()) {
        if (::ChainstateActive().IsInitialBlockDownload() && ppindex && *ppindex) {
            LogPrintf("Synchronizing blockheaders, height: %d (~%.2f%%)\n", (*ppindex)->nHeight, 100.0/((*ppindex)->nHeight+(GetAdjustedTime() - (*ppindex)->GetBlockTime()) / Params().GetConsensus().nPowTargetSpacing) * (*ppindex)->nHeight);
        }
    }
    return true;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
static FlatFilePos SaveBlockToDisk(const CBlock& block, int nHeight, const CChainParams& chainparams, const FlatFilePos* dbp) {
    unsigned int nBlockSize = ::GetSerializeSize(block, CLIENT_VERSION);
    FlatFilePos blockPos;
    if (dbp != nullptr)
        blockPos = *dbp;
    if (!FindBlockPos(blockPos, nBlockSize+8, nHeight, block.GetBlockTime(), dbp != nullptr)) {
        error("%s: FindBlockPos failed", __func__);
        return FlatFilePos();
    }
    if (dbp == nullptr) {
        if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart())) {
            AbortNode("Failed to write block");
            return FlatFilePos();
        }
    }
    return blockPos;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
bool CChainState::AcceptBlock(const std::shared_ptr<const CBlock>& pblock, BlockValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const FlatFilePos* dbp, bool* fNewBlock)
{
    const CBlock& block = *pblock;

    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    CBlockIndex *pindexDummy = nullptr;
    CBlockIndex *&pindex = ppindex ? *ppindex : pindexDummy;

    bool accepted_header = m_blockman.AcceptBlockHeader(block, state, chainparams, &pindex, fRequested);
    CheckBlockIndex(chainparams.GetConsensus());

    if (!accepted_header)
        return false;

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreOrSameWork = (m_chain.Tip() ? pindex->nChainWork >= m_chain.Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(m_chain.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: Decouple this function from the block download logic by removing fRequested
    // This requires some new chain data structure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {  // If we didn't ask for it:
        if (pindex->nTx != 0) return true;    // This is a previously-processed block that was pruned
        if (!fHasMoreOrSameWork) return true; // Don't process less-work chains
        if (fTooFarAhead) return true;        // Block height is too high

        // Protect against DoS attacks from low-work chains.
        // If our tip is behind, a peer could try to send us
        // low-work blocks on a fake chain that we would never
        // request; don't process these.
        if (pindex->nChainWork < nMinimumChainWork) return true;
    }

    if (!CheckBlock(block, state, chainparams.GetConsensus())) {
        return error("%s: %s", __func__, state.ToString());
    }

    if (block.IsProofOfStake()) {
        pindex->SetProofOfStake();
        pindex->prevoutStake = pblock->vtx[0]->vin[0].prevout;
        if (!pindex->pprev
            || (pindex->pprev->bnStakeModifier.IsNull()
                && pindex->pprev->GetBlockHash() != chainparams.GetConsensus().hashGenesisBlock)) {
            // Block received out of order
            if (fGhostMode && !IsInitialBlockDownload()) {
                if (pindex->nFlags & BLOCK_DELAYED) {
                    // Block is already delayed
                    state.nFlags |= BLOCK_DELAYED;
                    return true;
                }
                pindex->nFlags |= BLOCK_DELAYED;
                return DelayBlock(pblock, state);
            }
        } else {
            pindex->bnStakeModifier = ComputeStakeModifierV2(pindex->pprev, pindex->prevoutStake.hash);
        }
        pindex->nFlags &= ~BLOCK_DELAYED;
        setDirtyBlockIndex.insert(pindex);
    }

    if (!ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindex->pprev, true)) {
        if (state.IsInvalid() && state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pindex);
        }
        return error("%s: %s", __func__, state.ToString());
    }

    if (state.nFlags & BLOCK_STAKE_KERNEL_SPENT && !(state.nFlags & BLOCK_FAILED_DUPLICATE_STAKE)) {
        if (state.nodeId > -1) {
            IncPersistentMisbehaviour(state.nodeId, 20);
            Misbehaving(state.nodeId, 20, "Spent kernel");
        }
    }

    RemoveNodeHeader(pindex->GetBlockHash());
    pindex->nFlags |= BLOCK_ACCEPTED;
    setDirtyBlockIndex.insert(pindex);

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)
    if (!(state.nFlags & (BLOCK_STAKE_KERNEL_SPENT | BLOCK_FAILED_DUPLICATE_STAKE))
        && !IsInitialBlockDownload() && m_chain.Tip() == pindex->pprev) {
        GetMainSignals().NewPoWValidBlock(pindex, pblock);
    }

    // Write block to history file
    if (fNewBlock) *fNewBlock = true;
    try {
        FlatFilePos blockPos = SaveBlockToDisk(block, pindex->nHeight, chainparams, dbp);
        if (blockPos.IsNull()) {
            state.Error(strprintf("%s: Failed to find position to write new block to disk", __func__));
            return false;
        }
        ReceivedBlockTransactions(block, pindex, blockPos, chainparams.GetConsensus());
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    FlushStateToDisk(chainparams, state, FlushStateMode::NONE);

    CheckBlockIndex(chainparams.GetConsensus());

    return true;
}

bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool *fNewBlock, NodeId node_id)
{
    AssertLockNotHeld(cs_main);

    CBlockIndex *pindex = nullptr;
    {
        /*
        uint256 hash = pblock->GetHash();
        // Limited duplicity on stake: prevents block flood attack
        // Duplicate stake allowed only when there is orphan child block
        if (!fReindex && !fImporting && pblock->IsProofOfStake() && setStakeSeen.count(pblock->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash))
            return error("%s: Duplicate proof-of-stake (%s, %d) for block %s", pblock->GetProofOfStake().first.ToString(), pblock->GetProofOfStake().second, hash.ToString());
        */

        if (fNewBlock) *fNewBlock = false;
        BlockValidationState state;
        if (node_id > -1) {
            state.nodeId = node_id;
        }

        // CheckBlock() does not support multi-threaded block validation because CBlock::fChecked can cause data race.
        // Therefore, the following critical section must include the CheckBlock() call as well.
        LOCK(cs_main);

        // Ensure that CheckBlock() passes before calling AcceptBlock, as
        // belt-and-suspenders.
        bool ret = CheckBlock(*pblock, state, chainparams.GetConsensus());
        if (ret) {
            // Store to disk
            ret = ::ChainstateActive().AcceptBlock(pblock, state, chainparams, &pindex, fForceProcessing, nullptr, fNewBlock);
        }
        if (state.nFlags & BLOCK_DELAYED) {
            return true;
        }
        if (!ret) {
            if (fGhostMode) {
                // Mark block as invalid to prevent re-requesting from peer.
                // Block will have been added to the block index in AcceptBlockHeader
                CBlockIndex *pindex = ::ChainstateActive().m_blockman.AddToBlockIndex(*pblock);
                ::ChainstateActive().InvalidBlockFound(pindex, *pblock, state);
            }
            GetMainSignals().BlockChecked(*pblock, state);
            return error("%s: AcceptBlock FAILED (%s)", __func__, state.ToString());
        }

        if (pindex && state.nFlags & BLOCK_FAILED_DUPLICATE_STAKE) {
            pindex->nFlags |= BLOCK_FAILED_DUPLICATE_STAKE;
            setDirtyBlockIndex.insert(pindex);
            LogPrint(BCLog::POS, "%s Marking duplicate stake: %s.\n", __func__, pindex->GetBlockHash().ToString());
            GetMainSignals().BlockChecked(*pblock, state);
        }
    }

    NotifyHeaderTip();

    BlockValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!::ChainstateActive().ActivateBestChain(state, chainparams, pblock))
        return error("%s: ActivateBestChain failed (%s)", __func__, state.ToString());

    if (smsg::fSecMsgEnabled && gArgs.GetBoolArg("-smsgscanincoming", false)) {
        smsgModule.ScanBlock(*pblock);
    }

    {
        assert(pindex);
        // Check here for blocks not connected to the chain, TODO: move to a timer.
        CheckDelayedBlocks(chainparams, pindex->GetBlockHash());
    }

    return true;
}

bool TestBlockValidity(BlockValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW, bool fCheckMerkleRoot)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == ::ChainActive().Tip());
    CCoinsViewCache viewNew(&::ChainstateActive().CoinsTip());
    uint256 block_hash(block.GetHash());
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;
    indexDummy.phashBlock = &block_hash;

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev, GetAdjustedTime()))
        return error("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, state.ToString());
    if (!CheckBlock(block, state, chainparams.GetConsensus(), fCheckPOW, fCheckMerkleRoot))
        return error("%s: Consensus::CheckBlock: %s", __func__, state.ToString());
    if (!ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindexPrev))
        return error("%s: Consensus::ContextualCheckBlock: %s", __func__, state.ToString());
    if (!::ChainstateActive().ConnectBlock(block, state, &indexDummy, viewNew, chainparams, true))
        return false;
    assert(state.IsValid());

    return true;
}

/**
 * BLOCK PRUNING CODE
 */

/* Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage()
{
    LOCK(cs_LastBlockFile);

    uint64_t retval = 0;
    for (const CBlockFileInfo &file : vinfoBlockFile) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

/* Prune a block file (modify associated database entries)*/
void PruneOneBlockFile(const int fileNumber)
{
    LOCK(cs_LastBlockFile);

    for (const auto& entry : g_chainman.BlockIndex()) {
        CBlockIndex* pindex = entry.second;
        if (pindex->nFile == fileNumber) {
            pindex->nStatus &= ~BLOCK_HAVE_DATA;
            pindex->nStatus &= ~BLOCK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBlockIndex.insert(pindex);

            // Prune from m_blocks_unlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // m_blocks_unlinked or setBlockIndexCandidates.
            auto range = g_chainman.m_blockman.m_blocks_unlinked.equal_range(pindex->pprev);
            while (range.first != range.second) {
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator _it = range.first;
                range.first++;
                if (_it->second == pindex) {
                    g_chainman.m_blockman.m_blocks_unlinked.erase(_it);
                }
            }
        }
    }

    vinfoBlockFile[fileNumber].SetNull();
    setDirtyFileInfo.insert(fileNumber);
}


void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune)
{
    for (std::set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) {
        FlatFilePos pos(*it, 0);
        fs::remove(BlockFileSeq().FileName(pos));
        fs::remove(UndoFileSeq().FileName(pos));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

/* Calculate the block/rev files to delete based on height specified by user with RPC command pruneblockchain */
static void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight)
{
    assert(fPruneMode && nManualPruneHeight > 0);

    LOCK2(cs_main, cs_LastBlockFile);
    if (::ChainActive().Tip() == nullptr)
        return;

    // last block to prune is the lesser of (user-specified height, MIN_BLOCKS_TO_KEEP from the tip)
    unsigned int nLastBlockWeCanPrune = std::min((unsigned)nManualPruneHeight, ::ChainActive().Tip()->nHeight - MIN_BLOCKS_TO_KEEP);
    int count=0;
    for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
        if (vinfoBlockFile[fileNumber].nSize == 0 || vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
            continue;
        PruneOneBlockFile(fileNumber);
        setFilesToPrune.insert(fileNumber);
        count++;
    }
    LogPrintf("Prune (Manual): prune_height=%d removed %d blk/rev pairs\n", nLastBlockWeCanPrune, count);
}

/* This function is called from the RPC code for pruneblockchain */
void PruneBlockFilesManual(int nManualPruneHeight)
{
    BlockValidationState state;
    const CChainParams& chainparams = Params();
    if (!::ChainstateActive().FlushStateToDisk(
            chainparams, state, FlushStateMode::NONE, nManualPruneHeight)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, state.ToString());
    }
}

/**
 * Prune block and undo files (blk???.dat and undo???.dat) so that the disk space used is less than a user-defined target.
 * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
 * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
 * (which in this case means the blockchain must be re-downloaded.)
 *
 * Pruning functions are called from FlushStateToDisk when the global fCheckForPruning flag has been set.
 * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
 * Pruning cannot take place until the longest chain is at least a certain length (100000 on mainnet, 1000 on testnet, 1000 on regtest).
 * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
 * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
 * A db flag records the fact that at least some block files have been pruned.
 *
 * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
 */
static void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(cs_main, cs_LastBlockFile);
    if (::ChainActive().Tip() == nullptr || nPruneTarget == 0) {
        return;
    }
    if ((uint64_t)::ChainActive().Tip()->nHeight <= nPruneAfterHeight) {
        return;
    }

    unsigned int nLastBlockWeCanPrune = ::ChainActive().Tip()->nHeight - MIN_BLOCKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count=0;

    if (nCurrentUsage + nBuffer >= nPruneTarget) {
        // On a prune event, the chainstate DB is flushed.
        // To avoid excessive prune events negating the benefit of high dbcache
        // values, we should not prune too rapidly.
        // So when pruning in IBD, increase the buffer a bit to avoid a re-prune too soon.
        if (::ChainstateActive().IsInitialBlockDownload()) {
            // Since this is only relevant during IBD, we use a fixed 10%
            nBuffer += nPruneTarget / 10;
        }

        for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
            nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

            if (vinfoBlockFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < nPruneTarget)  // are we below our target?
                break;

            // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep scanning
            if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                continue;

            PruneOneBlockFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    LogPrint(BCLog::PRUNE, "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
           nPruneTarget/1024/1024, nCurrentUsage/1024/1024,
           ((int64_t)nPruneTarget - (int64_t)nCurrentUsage)/1024/1024,
           nLastBlockWeCanPrune, count);
}

static FlatFileSeq BlockFileSeq()
{
    return FlatFileSeq(GetBlocksDir(), "blk", BLOCKFILE_CHUNK_SIZE);
}

static FlatFileSeq UndoFileSeq()
{
    return FlatFileSeq(GetBlocksDir(), "rev", UNDOFILE_CHUNK_SIZE);
}

FILE* OpenBlockFile(const FlatFilePos &pos, bool fReadOnly) {
    return BlockFileSeq().Open(pos, fReadOnly);
}

/** Open an undo file (rev?????.dat) */
static FILE* OpenUndoFile(const FlatFilePos &pos, bool fReadOnly) {
    return UndoFileSeq().Open(pos, fReadOnly);
}

fs::path GetBlockPosFilename(const FlatFilePos &pos)
{
    return BlockFileSeq().FileName(pos);
}

CBlockIndex * BlockManager::InsertBlockIndex(const uint256& hash)
{
    AssertLockHeld(cs_main);

    if (hash.IsNull())
        return nullptr;

    // Return existing
    BlockMap::iterator mi = m_block_index.find(hash);
    if (mi != m_block_index.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    mi = m_block_index.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool BlockManager::LoadBlockIndex(
    const Consensus::Params& consensus_params,
    CBlockTreeDB& blocktree,
    std::set<CBlockIndex*, CBlockIndexWorkComparator>& block_index_candidates)
{
    if (!blocktree.LoadBlockIndexGuts(consensus_params, [this](const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return this->InsertBlockIndex(hash); }))
        return false;

    // Calculate nChainWork
    std::vector<std::pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(m_block_index.size());
    for (const std::pair<const uint256, CBlockIndex*>& item : m_block_index)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for (const std::pair<int, CBlockIndex*>& item : vSortedByHeight)
    {
        if (ShutdownRequested()) return false;
        CBlockIndex* pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + GetBlockProof(*pindex);
        pindex->nTimeMax = (pindex->pprev ? std::max(pindex->pprev->nTimeMax, pindex->nTime) : pindex->nTime);
        // We can link the chain of blocks for which we've received transactions at some point.
        // Pruned nodes may have deleted the block.
        if (pindex->nTx > 0) {
            if (pindex->pprev) {
                if (pindex->pprev->HaveTxsDownloaded()) {
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                } else {
                    pindex->nChainTx = 0;
                    m_blocks_unlinked.insert(std::make_pair(pindex->pprev, pindex));
                }
            } else {
                pindex->nChainTx = pindex->nTx;
            }
        }
        if (!(pindex->nStatus & BLOCK_FAILED_MASK) && pindex->pprev && (pindex->pprev->nStatus & BLOCK_FAILED_MASK)) {
            pindex->nStatus |= BLOCK_FAILED_CHILD;
            setDirtyBlockIndex.insert(pindex);
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->HaveTxsDownloaded() || pindex->pprev == nullptr)) {
            block_index_candidates.insert(pindex);
        }
        if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid || pindex->nChainWork > pindexBestInvalid->nChainWork))
            pindexBestInvalid = pindex;
        if (pindex->pprev)
            pindex->BuildSkip();
        if (pindex->IsValid(BLOCK_VALID_TREE) && (pindexBestHeader == nullptr || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
            pindexBestHeader = pindex;
    }

    return true;
}

void BlockManager::Unload() {
    m_failed_blocks.clear();
    m_blocks_unlinked.clear();

    for (const BlockMap::value_type& entry : m_block_index) {
        delete entry.second;
    }

    m_block_index.clear();
}

bool static LoadBlockIndexDB(const CChainParams& chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!g_chainman.m_blockman.LoadBlockIndex(
            chainparams.GetConsensus(), *pblocktree,
            ::ChainstateActive().setBlockIndexCandidates)) {
        return false;
    }

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) {
        CBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info)) {
            vinfoBlockFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    std::set<int> setBlkDataFiles;
    for (const std::pair<const uint256, CBlockIndex*>& item : g_chainman.BlockIndex())
    {
        CBlockIndex* pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA) {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++)
    {
        FlatFilePos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    // Check whether we have ever pruned block & undo files
    pblocktree->ReadFlag("prunedblockfiles", fHavePruned);
    if (fHavePruned)
        LogPrintf("LoadBlockIndexDB(): Block files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    if(fReindexing) fReindex = true;

    // Check whether we have an address index
    pblocktree->ReadFlag("addressindex", fAddressIndex);
    LogPrintf("%s: address index %s\n", __func__, fAddressIndex ? "enabled" : "disabled");

    // Check whether we have a timestamp index
    pblocktree->ReadFlag("timestampindex", fTimestampIndex);
    LogPrintf("%s: timestamp index %s\n", __func__, fTimestampIndex ? "enabled" : "disabled");

    // Check whether we have a spent index
    pblocktree->ReadFlag("spentindex", fSpentIndex);
    LogPrintf("%s: spent index %s\n", __func__, fSpentIndex ? "enabled" : "disabled");

    return true;
}

bool CChainState::LoadChainTip(const CChainParams& chainparams)
{
    AssertLockHeld(cs_main);
    const CCoinsViewCache& coins_cache = CoinsTip();
    assert(!coins_cache.GetBestBlock().IsNull()); // Never called when the coins view is empty
    const CBlockIndex* tip = m_chain.Tip();

    if (tip && tip->GetBlockHash() == coins_cache.GetBestBlock()) {
        return true;
    }

    // Load pointer to end of best chain
    CBlockIndex* pindex = LookupBlockIndex(coins_cache.GetBestBlock());
    if (!pindex) {
        return false;
    }
    m_chain.SetTip(pindex);
    PruneBlockIndexCandidates();

    tip = m_chain.Tip();
    LogPrintf("Loaded best chain: hashBestChain=%s height=%d date=%s progress=%f\n",
        tip->GetBlockHash().ToString(),
        m_chain.Height(),
        FormatISO8601DateTime(tip->GetBlockTime()),
        GuessVerificationProgress(chainparams.TxData(), tip));
    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying blocks...").translated, 0, false);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100, false);
}

bool CVerifyDB::VerifyDB(const CChainParams& chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth)
{
    LOCK(cs_main);
    if (::ChainActive().Tip() == nullptr || ::ChainActive().Tip()->pprev == nullptr)
        return true;

    fVerifyingDB = true;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0 || nCheckDepth > ::ChainActive().Height())
        nCheckDepth = ::ChainActive().Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CBlockIndex* pindex;
    CBlockIndex* pindexFailure = nullptr;
    int nGoodTransactions = 0;
    BlockValidationState state;
    int reportDone = 0;
    LogPrintf("[0%%]..."); /* Continued */
    for (pindex = ::ChainActive().Tip(); pindex && pindex->pprev; pindex = pindex->pprev) {
        boost::this_thread::interruption_point();
        const int percentageDone = std::max(1, std::min(99, (int)(((double)(::ChainActive().Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone/10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone); /* Continued */
            reportDone = percentageDone/10;
        }
        uiInterface.ShowProgress(_("Verifying blocks...").translated, percentageDone, false);
        if (pindex->nHeight <= ::ChainActive().Height()-nCheckDepth)
            break;
        if (fPruneMode && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, only go back as far as we have data.
            LogPrintf("VerifyDB(): block verification stopping at height %d (pruning, no data)\n", pindex->nHeight);
            break;
        }
        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
            return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, chainparams.GetConsensus()))
            return error("%s: *** found bad block at %d, hash=%s (%s)\n", __func__,
                         pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString());
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            if (!pindex->GetUndoPos().IsNull()) {
                if (!UndoReadFromDisk(undo, pindex)) {
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                }
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && (coins.DynamicMemoryUsage() + ::ChainstateActive().CoinsTip().DynamicMemoryUsage()) <= nCoinCacheUsage) {
            assert(coins.GetBestBlock() == pindex->GetBlockHash());
            DisconnectResult res = ::ChainstateActive().DisconnectBlock(block, pindex, coins);
            if (res == DISCONNECT_FAILED) {
                return error("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
            if (res == DISCONNECT_UNCLEAN) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else {
                nGoodTransactions += block.vtx.size();
            }
        }
        if (ShutdownRequested())
            return true;
    }
    if (pindexFailure)
        return error("VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", ::ChainActive().Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // store block count as we move pindex at check level >= 4
    int block_count = ::ChainActive().Height() - pindex->nHeight;

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        while (pindex != ::ChainActive().Tip()) {
            boost::this_thread::interruption_point();
            const int percentageDone = std::max(1, std::min(99, 100 - (int)(((double)(::ChainActive().Height() - pindex->nHeight)) / (double)nCheckDepth * 50)));
            if (reportDone < percentageDone/10) {
                // report every 10% step
                LogPrintf("[%d%%]...", percentageDone); /* Continued */
                reportDone = percentageDone/10;
            }
            uiInterface.ShowProgress(_("Verifying blocks...").translated, percentageDone, false);
            pindex = ::ChainActive().Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
                return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            if (!::ChainstateActive().ConnectBlock(block, state, pindex, coins, chainparams))
                return error("VerifyDB(): *** found unconnectable block at %d, hash=%s (%s)", pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString());
        }
    }

    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", block_count, nGoodTransactions);
    fVerifyingDB = false;

    return true;
}

/** Apply the effects of a block on the utxo cache, ignoring that it may already have been applied. */
bool CChainState::RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs, const CChainParams& params)
{
    // TODO: merge with ConnectBlock
    CBlock block;
    if (!ReadBlockFromDisk(block, pindex, params.GetConsensus())) {
        return error("ReplayBlock(): ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
    }

    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const CTxIn &txin : tx->vin) {
                inputs.SpendCoin(txin.prevout);
            }
        }
        // Pass check = true as every addition may be an overwrite.
        AddCoins(inputs, *tx, pindex->nHeight, true);
    }
    return true;
}

bool CChainState::ReplayBlocks(const CChainParams& params)
{
    LOCK(cs_main);

    CCoinsView& db = this->CoinsDB();
    CCoinsViewCache cache(&db);

    std::vector<uint256> hashHeads = db.GetHeadBlocks();
    if (hashHeads.empty()) return true; // We're already in a consistent state.
    if (hashHeads.size() != 2) return error("ReplayBlocks(): unknown inconsistent state");

    uiInterface.ShowProgress(_("Replaying blocks...").translated, 0, false);
    LogPrintf("Replaying blocks\n");

    const CBlockIndex* pindexOld = nullptr;  // Old tip during the interrupted flush.
    const CBlockIndex* pindexNew;            // New tip during the interrupted flush.
    const CBlockIndex* pindexFork = nullptr; // Latest block common to both the old and the new tip.

    if (m_blockman.m_block_index.count(hashHeads[0]) == 0) {
        return error("ReplayBlocks(): reorganization to unknown block requested");
    }
    pindexNew = m_blockman.m_block_index[hashHeads[0]];

    if (!hashHeads[1].IsNull()) { // The old tip is allowed to be 0, indicating it's the first flush.
        if (m_blockman.m_block_index.count(hashHeads[1]) == 0) {
            return error("ReplayBlocks(): reorganization from unknown block requested");
        }
        pindexOld = m_blockman.m_block_index[hashHeads[1]];
        pindexFork = LastCommonAncestor(pindexOld, pindexNew);
        assert(pindexFork != nullptr);
    }

    // Rollback along the old branch.
    while (pindexOld != pindexFork) {
        if (pindexOld->nHeight > 0) { // Never disconnect the genesis block.
            CBlock block;
            if (!ReadBlockFromDisk(block, pindexOld, params.GetConsensus())) {
                return error("RollbackBlock(): ReadBlockFromDisk() failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            LogPrintf("Rolling back %s (%i)\n", pindexOld->GetBlockHash().ToString(), pindexOld->nHeight);
            DisconnectResult res = DisconnectBlock(block, pindexOld, cache);
            if (res == DISCONNECT_FAILED) {
                return error("RollbackBlock(): DisconnectBlock failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            // If DISCONNECT_UNCLEAN is returned, it means a non-existing UTXO was deleted, or an existing UTXO was
            // overwritten. It corresponds to cases where the block-to-be-disconnect never had all its operations
            // applied to the UTXO set. However, as both writing a UTXO and deleting a UTXO are idempotent operations,
            // the result is still a version of the UTXO set with the effects of that block undone.
        }
        pindexOld = pindexOld->pprev;
    }

    // Roll forward from the forking point to the new tip.
    int nForkHeight = pindexFork ? pindexFork->nHeight : 0;
    for (int nHeight = nForkHeight + 1; nHeight <= pindexNew->nHeight; ++nHeight) {
        const CBlockIndex* pindex = pindexNew->GetAncestor(nHeight);
        LogPrintf("Rolling forward %s (%i)\n", pindex->GetBlockHash().ToString(), nHeight);
        uiInterface.ShowProgress(_("Replaying blocks...").translated, (int) ((nHeight - nForkHeight) * 100.0 / (pindexNew->nHeight - nForkHeight)) , false);
        if (!RollforwardBlock(pindex, cache, params)) return false;
    }

    cache.SetBestBlock(pindexNew->GetBlockHash(), pindexNew->nHeight);
    cache.Flush();
    uiInterface.ShowProgress("", 100, false);
    return true;
}

//! Helper for CChainState::RewindBlockIndex
void CChainState::EraseBlockData(CBlockIndex* index)
{
    AssertLockHeld(cs_main);
    assert(!m_chain.Contains(index)); // Make sure this block isn't active

    // Reduce validity
    index->nStatus = std::min<unsigned int>(index->nStatus & BLOCK_VALID_MASK, BLOCK_VALID_TREE) | (index->nStatus & ~BLOCK_VALID_MASK);
    // Remove have-data flags.
    index->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
    // Remove storage location.
    index->nFile = 0;
    index->nDataPos = 0;
    index->nUndoPos = 0;
    // Remove various other things
    index->nTx = 0;
    index->nChainTx = 0;
    index->nSequenceId = 0;
    // Make sure it gets written.
    setDirtyBlockIndex.insert(index);
    // Update indexes
    setBlockIndexCandidates.erase(index);
    auto ret = m_blockman.m_blocks_unlinked.equal_range(index->pprev);
    while (ret.first != ret.second) {
        if (ret.first->second == index) {
            m_blockman.m_blocks_unlinked.erase(ret.first++);
        } else {
            ++ret.first;
        }
    }
    // Mark parent as eligible for main chain again
    if (index->pprev && index->pprev->IsValid(BLOCK_VALID_TRANSACTIONS) && index->pprev->HaveTxsDownloaded()) {
        setBlockIndexCandidates.insert(index->pprev);
    }
}

bool CChainState::RewindBlockIndex(const CChainParams& params)
{
    // Note that during -reindex-chainstate we are called with an empty m_chain!

    // First erase all post-segwit blocks without witness not in the main chain,
    // as this can we done without costly DisconnectTip calls. Active
    // blocks will be dealt with below (releasing cs_main in between).
    {
        LOCK(cs_main);
        for (const auto& entry : m_blockman.m_block_index) {
            if (IsWitnessEnabled(entry.second->pprev, params.GetConsensus()) && !(entry.second->nStatus & BLOCK_OPT_WITNESS) && !m_chain.Contains(entry.second)) {
                EraseBlockData(entry.second);
            }
        }
    }

    // Find what height we need to reorganize to.
    CBlockIndex *tip;
    int nHeight = 1;
    {
        LOCK(cs_main);
        while (nHeight <= m_chain.Height()) {
            // Although SCRIPT_VERIFY_WITNESS is now generally enforced on all
            // blocks in ConnectBlock, we don't need to go back and
            // re-download/re-verify blocks from before segwit actually activated.
            if (IsWitnessEnabled(m_chain[nHeight - 1], params.GetConsensus()) && !(m_chain[nHeight]->nStatus & BLOCK_OPT_WITNESS)) {
                break;
            }
            nHeight++;
        }

        tip = m_chain.Tip();
    }
    // nHeight is now the height of the first insufficiently-validated block, or tipheight + 1

    BlockValidationState state;
    // Loop until the tip is below nHeight, or we reach a pruned block.
    while (!ShutdownRequested()) {
        {
            LOCK2(cs_main, ::mempool.cs);
            // Make sure nothing changed from under us (this won't happen because RewindBlockIndex runs before importing/network are active)
            assert(tip == m_chain.Tip());
            if (tip == nullptr || tip->nHeight < nHeight) break;
            if (fPruneMode && !(tip->nStatus & BLOCK_HAVE_DATA)) {
                // If pruning, don't try rewinding past the HAVE_DATA point;
                // since older blocks can't be served anyway, there's
                // no need to walk further, and trying to DisconnectTip()
                // will fail (and require a needless reindex/redownload
                // of the blockchain).
                break;
            }

            // Disconnect block
            if (!DisconnectTip(state, params, nullptr)) {
                return error("RewindBlockIndex: unable to disconnect block at height %i (%s)", tip->nHeight, state.ToString());
            }

            // Reduce validity flag and have-data flags.
            // We do this after actual disconnecting, otherwise we'll end up writing the lack of data
            // to disk before writing the chainstate, resulting in a failure to continue if interrupted.
            // Note: If we encounter an insufficiently validated block that
            // is on m_chain, it must be because we are a pruning node, and
            // this block or some successor doesn't HAVE_DATA, so we were unable to
            // rewind all the way.  Blocks remaining on m_chain at this point
            // must not have their validity reduced.
            EraseBlockData(tip);

            tip = tip->pprev;
        }
        // Make sure the queue of validation callbacks doesn't grow unboundedly.
        LimitValidationInterfaceQueue();

        // Occasionally flush state to disk.
        if (!FlushStateToDisk(params, state, FlushStateMode::PERIODIC)) {
            LogPrintf("RewindBlockIndex: unable to flush state to disk (%s)\n", state.ToString());
            return false;
        }
    }

    {
        LOCK(cs_main);
        if (m_chain.Tip() != nullptr) {
            // We can't prune block index candidates based on our tip if we have
            // no tip due to m_chain being empty!
            PruneBlockIndexCandidates();

            CheckBlockIndex(params.GetConsensus());

            // FlushStateToDisk can possibly read ::ChainActive(). Be conservative
            // and skip it here, we're about to -reindex-chainstate anyway, so
            // it'll get called a bunch real soon.
            BlockValidationState state;
            if (!FlushStateToDisk(params, state, FlushStateMode::ALWAYS)) {
                LogPrintf("RewindBlockIndex: unable to flush state to disk (%s)\n", state.ToString());
                return false;
            }
        }
    }

    return true;
}

void CChainState::UnloadBlockIndex() {
    nBlockSequenceId = 1;
    setBlockIndexCandidates.clear();
}

// May NOT be used after any connections are up as much
// of the peer-processing logic assumes a consistent
// block index state
void UnloadBlockIndex()
{
    LOCK(cs_main);
    g_chainman.Unload();
    pindexBestInvalid = nullptr;
    pindexBestHeader = nullptr;
    mempool.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    setDirtyBlockIndex.clear();
    setDirtyFileInfo.clear();
    versionbitscache.Clear();
    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].clear();
    }
    fHavePruned = false;
}

bool ShouldAutoReindex()
{
    // Force reindex to update version
    bool nV1 = false;
    if (!pblocktree->ReadFlag("v1", nV1) || !nV1) {
        LogPrintf("%s: v1 marker not detected, attempting reindex.\n", __func__);
        return true;
    }
    return false;
};

bool RebuildRollingIndices()
{
    bool nV2 = false;
    if (gArgs.GetBoolArg("-rebuildrollingindices", false)) {
        LogPrintf("%s: Manual override, attempting to rewind chain.\n", __func__);
    } else
    if (pblocktree->ReadFlag("v2", nV2) && nV2) {
        return true;
    } else {
        LogPrintf("%s: v2 marker not detected, attempting to rewind chain.\n", __func__);
    }
    uiInterface.InitMessage(_("Rebuilding rolling indices...").translated);

    int64_t now = GetAdjustedTime();
    int rewound_tip_height, max_height_to_keep = 0;

    {
        LOCK(cs_main);
        CBlockIndex *pindex_tip = ::ChainActive().Tip();
        CBlockIndex *pindex = pindex_tip;
        while (pindex && pindex->nTime >= now - smsg::KEEP_FUNDING_TX_DATA) {
            max_height_to_keep = pindex->nHeight;
            pindex = ::ChainActive()[pindex->nHeight-1];
        }

        LogPrintf("%s: Rewinding to block %d.\n", __func__, max_height_to_keep);
        int num_disconnected = 0;

        std::string str_error;
        if (!RewindToHeight(max_height_to_keep, num_disconnected, str_error)) {
            LogPrintf("%s: RewindToHeight failed %s.\n", __func__, str_error);
            return false;
        }
        rewound_tip_height = ::ChainActive().Tip()->nHeight;
    }

    const CChainParams& chainparams = Params();
    BlockValidationState state;
    if (!ActivateBestChain(state, chainparams)) {
        LogPrintf("%s: ActivateBestChain failed %s.\n", __func__, state.ToString());
        return false;
    }

    {
        LOCK(cs_main);
        LogPrintf("%s: Reprocessed chain from block %d to %d.\n", __func__, rewound_tip_height, ::ChainActive().Tip()->nHeight);

        if (!pblocktree->WriteFlag("v2", true)) {
            LogPrintf("%s: WriteFlag failed.\n", __func__);
            return false;
        }
    }
    return true;
}

bool LoadBlockIndex(const CChainParams& chainparams)
{
    // Load block index from databases
    bool needs_init = fReindex;

    if (!fReindex) {
        bool ret = LoadBlockIndexDB(chainparams);
        if (!ret) return false;
        needs_init = g_chainman.m_blockman.m_block_index.empty();
    }

    if (needs_init) {
        // Everything here is for *new* reindex/DBs. Thus, though
        // LoadBlockIndexDB may have set fReindex if we shut down
        // mid-reindex previously, we don't check fReindex and
        // instead only check it prior to LoadBlockIndexDB to set
        // needs_init.

        LogPrintf("Initializing databases...\n");
        pblocktree->WriteFlag("v1", true);
        pblocktree->WriteFlag("v2", true);

        // Use the provided setting for -addressindex in the new database
        fAddressIndex = gArgs.GetBoolArg("-addressindex", DEFAULT_ADDRESSINDEX);
        pblocktree->WriteFlag("addressindex", fAddressIndex);
        LogPrintf("%s: address index %s\n", __func__, fAddressIndex ? "enabled" : "disabled");

        // Use the provided setting for -timestampindex in the new database
        fTimestampIndex = gArgs.GetBoolArg("-timestampindex", DEFAULT_TIMESTAMPINDEX);
        pblocktree->WriteFlag("timestampindex", fTimestampIndex);
        LogPrintf("%s: timestamp index %s\n", __func__, fTimestampIndex ? "enabled" : "disabled");

        // Use the provided setting for -spentindex in the new database
        fSpentIndex = gArgs.GetBoolArg("-spentindex", DEFAULT_SPENTINDEX);
        pblocktree->WriteFlag("spentindex", fSpentIndex);
        LogPrintf("%s: spent index %s\n", __func__, fSpentIndex ? "enabled" : "disabled");
    }
    return true;
}

bool CChainState::LoadGenesisBlock(const CChainParams& chainparams)
{
    LOCK(cs_main);

    // Check whether we're already initialized by checking for genesis in
    // m_blockman.m_block_index. Note that we can't use m_chain here, since it is
    // set based on the coins db, not the block index db, which is the only
    // thing loaded at this point.
    if (m_blockman.m_block_index.count(chainparams.GenesisBlock().GetHash()))
        return true;

    try {
        const CBlock& block = chainparams.GenesisBlock();
        FlatFilePos blockPos = SaveBlockToDisk(block, 0, chainparams, nullptr);
        if (blockPos.IsNull())
            return error("%s: writing genesis block to disk failed", __func__);
        CBlockIndex *pindex = m_blockman.AddToBlockIndex(block);
        pindex->nFlags |= BLOCK_ACCEPTED;
        ReceivedBlockTransactions(block, pindex, blockPos, chainparams.GetConsensus());
    } catch (const std::runtime_error& e) {
        return error("%s: failed to write genesis block: %s", __func__, e.what());
    }

    return true;
}

bool LoadGenesisBlock(const CChainParams& chainparams)
{
    return ::ChainstateActive().LoadGenesisBlock(chainparams);
}

void LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, FlatFilePos* dbp)
{
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, FlatFilePos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    fAddressIndex = gArgs.GetBoolArg("-addressindex", DEFAULT_ADDRESSINDEX);
    fTimestampIndex = gArgs.GetBoolArg("-timestampindex", DEFAULT_TIMESTAMPINDEX);
    fSpentIndex = gArgs.GetBoolArg("-spentindex", DEFAULT_SPENTINDEX);

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            if (ShutdownRequested()) return;

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(chainparams.MessageStart()[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> buf;
                if (memcmp(buf, chainparams.MessageStart(), CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SERIALIZED_SIZE)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
                CBlock& block = *pblock;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                uint256 hash = block.GetHash();
                {
                    LOCK(cs_main);
                    // detect out of order blocks, and store them for later
                    if (hash != chainparams.GetConsensus().hashGenesisBlock && !LookupBlockIndex(block.hashPrevBlock)) {
                        LogPrint(BCLog::REINDEX, "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                                block.hashPrevBlock.ToString());
                        if (dbp)
                            mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                        continue;
                    }

                    // process in case the block isn't known yet
                    CBlockIndex* pindex = LookupBlockIndex(hash);
                    if (!pindex || (pindex->nStatus & BLOCK_HAVE_DATA) == 0) {
                      BlockValidationState state;
                      if (::ChainstateActive().AcceptBlock(pblock, state, chainparams, nullptr, true, dbp, nullptr)) {
                          nLoaded++;
                      }
                      if (state.IsError()) {
                          break;
                      }
                    } else if (hash != chainparams.GetConsensus().hashGenesisBlock && pindex->nHeight % 1000 == 0) {
                      LogPrint(BCLog::REINDEX, "Block Import: already had block %s at height %d\n", hash.ToString(), pindex->nHeight);
                    }
                }

                // Activate the genesis block so normal node progress can continue
                if (hash == chainparams.GetConsensus().hashGenesisBlock) {
                    BlockValidationState state;
                    if (!ActivateBestChain(state, chainparams, nullptr)) {
                        break;
                    }
                }

                NotifyHeaderTip();

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, FlatFilePos>::iterator, std::multimap<uint256, FlatFilePos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, FlatFilePos>::iterator it = range.first;
                        std::shared_ptr<CBlock> pblockrecursive = std::make_shared<CBlock>();
                        if (ReadBlockFromDisk(*pblockrecursive, it->second, chainparams.GetConsensus()))
                        {
                            LogPrint(BCLog::REINDEX, "%s: Processing out of order child %s of %s\n", __func__, pblockrecursive->GetHash().ToString(),
                                    head.ToString());
                            LOCK(cs_main);
                            BlockValidationState dummy;
                            if (::ChainstateActive().AcceptBlock(pblockrecursive, dummy, chainparams, nullptr, true, &it->second, nullptr))
                            {
                                nLoaded++;
                                queue.push_back(pblockrecursive->GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                        NotifyHeaderTip();
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
}

void CChainState::CheckBlockIndex(const Consensus::Params& consensusParams)
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in m_blockman.m_block_index but no active chain. (A few of the
    // tests when iterating the block tree require that m_chain has been initialized.)
    if (m_chain.Height() < 0) {
        assert(m_blockman.m_block_index.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*,CBlockIndex*> forward;
    for (const std::pair<const uint256, CBlockIndex*>& entry : m_blockman.m_block_index) {
        forward.insert(std::make_pair(entry.second->pprev, entry.second));
    }

    assert(forward.size() == m_blockman.m_block_index.size());

    std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(nullptr);
    CBlockIndex *pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent nullptr.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = nullptr; // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = nullptr; // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNeverProcessed = nullptr; // Oldest ancestor of pindex for which nTx == 0.
    CBlockIndex* pindexFirstNotTreeValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotTransactionsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != nullptr) {
        nNodes++;
        if (pindexFirstInvalid == nullptr && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        if (pindexFirstMissing == nullptr && !(pindex->nStatus & BLOCK_HAVE_DATA)) pindexFirstMissing = pindex;
        if (pindexFirstNeverProcessed == nullptr && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTreeValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTransactionsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) pindexFirstNotTransactionsValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotChainValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) pindexFirstNotChainValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotScriptsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == nullptr) {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == consensusParams.hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == m_chain.Genesis()); // The current active chain's genesis block must be this block.
        }
        if (!pindex->HaveTxsDownloaded()) assert(pindex->nSequenceId <= 0); // nSequenceId can't be set positive for blocks that aren't linked (negative is used for preciousblock)
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!fHavePruned) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } else {
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pindex->nStatus & BLOCK_HAVE_DATA) assert(pindex->nTx > 0);
        }
        if (pindex->nStatus & BLOCK_HAVE_UNDO) assert(pindex->nStatus & BLOCK_HAVE_DATA);
        assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to HaveTxsDownloaded().
        assert((pindexFirstNeverProcessed == nullptr) == pindex->HaveTxsDownloaded());
        assert((pindexFirstNotTransactionsValid == nullptr) == pindex->HaveTxsDownloaded());
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        assert(pindex->pprev == nullptr || pindex->nChainWork >= pindex->pprev->nChainWork); // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == nullptr); // All m_blockman.m_block_index entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == nullptr); // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == nullptr); // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == nullptr); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == nullptr) {
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, m_chain.Tip()) && pindexFirstNeverProcessed == nullptr) {
            if (pindexFirstInvalid == nullptr) {
                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  m_chain.Tip() must also be there
                // even if some data has been pruned.
                if (pindexFirstMissing == nullptr || pindex == m_chain.Tip()) {
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in m_blocks_unlinked -- see test below.
            }
        } else { // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in m_blocks_unlinked.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeUnlinked = m_blockman.m_blocks_unlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != nullptr && pindexFirstInvalid == nullptr) {
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in m_blocks_unlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in m_blocks_unlinked if we don't HAVE_DATA
        if (pindexFirstMissing == nullptr) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in m_blocks_unlinked.
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed == nullptr && pindexFirstMissing != nullptr) {
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(fHavePruned); // We must have pruned.
            // This block may have entered m_blocks_unlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between m_chain and the
            //    tip.
            // So if this block is itself better than m_chain.Tip() and it wasn't in
            // setBlockIndexCandidates, then it must be in m_blocks_unlinked.
            if (!CBlockIndexWorkComparator()(pindex, m_chain.Tip()) && setBlockIndexCandidates.count(pindex) == 0) {
                if (pindexFirstInvalid == nullptr) {
                    assert(foundInUnlinked);
                }
            }
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = nullptr;
            if (pindex == pindexFirstMissing) pindexFirstMissing = nullptr;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = nullptr;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = nullptr;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = nullptr;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = nullptr;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = nullptr;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

std::string CChainState::ToString()
{
    CBlockIndex* tip = m_chain.Tip();
    return strprintf("Chainstate [%s] @ height %d (%s)",
        m_from_snapshot_blockhash.IsNull() ? "ibd" : "snapshot",
        tip ? tip->nHeight : -1, tip ? tip->GetBlockHash().ToString() : "null");
}

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, FormatISO8601Date(nTimeFirst), FormatISO8601Date(nTimeLast));
}

CBlockFileInfo* GetBlockFileInfo(size_t n)
{
    LOCK(cs_LastBlockFile);

    return &vinfoBlockFile.at(n);
}

ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsState(::ChainActive().Tip(), params, pos, versionbitscache);
}

BIP9Stats VersionBitsTipStatistics(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStatistics(::ChainActive().Tip(), params, pos);
}

int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStateSinceHeight(::ChainActive().Tip(), params, pos, versionbitscache);
}

static const uint64_t MEMPOOL_DUMP_VERSION = 1;

bool LoadMempool(CTxMemPool& pool)
{
    const CChainParams& chainparams = Params();
    int64_t nExpiryTimeout = gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60;
    FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat", "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open mempool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t expired = 0;
    int64_t failed = 0;
    int64_t already_there = 0;
    int64_t unbroadcast = 0;
    int64_t nNow = GetTime();

    try {
        uint64_t version;
        file >> version;
        if (version != MEMPOOL_DUMP_VERSION) {
            return false;
        }
        uint64_t num;
        file >> num;
        while (num--) {
            CTransactionRef tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta) {
                pool.PrioritiseTransaction(tx->GetHash(), amountdelta);
            }
            TxValidationState state;
            CBlockIndex* tip = ::ChainActive().Tip();
            assert(tip);
            const Consensus::Params &consensus = Params().GetConsensus();
            state.SetStateInfo(tip->nTime, tip->nHeight, consensus, fGhostMode, (fBusyImporting && fSkipRangeproof));
            if (nTime + nExpiryTimeout > nNow) {
                LOCK(cs_main);
                AcceptToMemoryPoolWithTime(chainparams, pool, state, tx, nTime,
                                           nullptr /* plTxnReplaced */, false /* bypass_limits */, 0 /* nAbsurdFee */,
                                           false /* test_accept */, false /* ignore_locks */);
                if (state.IsValid()) {
                    ++count;
                } else {
                    // mempool may contain the transaction already, e.g. from
                    // wallet(s) having loaded it while we were processing
                    // mempool transactions; consider these as valid, instead of
                    // failed, but mark them as 'already there'
                    if (pool.exists(tx->GetHash())) {
                        ++already_there;
                    } else {
                        ++failed;
                    }
                }
            } else {
                ++expired;
            }
            if (ShutdownRequested())
                return false;
        }
        std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto& i : mapDeltas) {
            pool.PrioritiseTransaction(i.first, i.second);
        }

        std::set<uint256> unbroadcast_txids;
        file >> unbroadcast_txids;
        unbroadcast = unbroadcast_txids.size();

        for (const auto& txid : unbroadcast_txids) {
            pool.AddUnbroadcastTx(txid);
        }

    } catch (const std::exception& e) {
        LogPrintf("Failed to deserialize mempool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LogPrintf("Imported mempool transactions from disk: %i succeeded, %i failed, %i expired, %i already there, %i waiting for initial broadcast\n", count, failed, expired, already_there, unbroadcast);
    return true;
}

bool DumpMempool(const CTxMemPool& pool)
{
    int64_t start = GetTimeMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vinfo;
    std::set<uint256> unbroadcast_txids;

    static Mutex dump_mutex;
    LOCK(dump_mutex);

    {
        LOCK(pool.cs);
        for (const auto &i : pool.mapDeltas) {
            mapDeltas[i.first] = i.second;
        }
        vinfo = pool.infoAll();
        unbroadcast_txids = pool.GetUnbroadcastTxs();
    }

    int64_t mid = GetTimeMicros();

    try {
        FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat.new", "wb");
        if (!filestr) {
            return false;
        }

        CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

        uint64_t version = MEMPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vinfo.size();
        for (const auto& i : vinfo) {
            file << *(i.tx);
            file << int64_t{count_seconds(i.m_time)};
            file << int64_t{i.nFeeDelta};
            mapDeltas.erase(i.tx->GetHash());
        }
        file << mapDeltas;

        LogPrintf("Writing %d unbroadcast transactions to disk.\n", unbroadcast_txids.size());
        file << unbroadcast_txids;

        if (!FileCommit(file.Get()))
            throw std::runtime_error("FileCommit failed");
        file.fclose();
        RenameOver(GetDataDir() / "mempool.dat.new", GetDataDir() / "mempool.dat");
        int64_t last = GetTimeMicros();
        LogPrintf("Dumped mempool: %gs to copy, %gs to dump\n", (mid-start)*MICRO, (last-mid)*MICRO);
    } catch (const std::exception& e) {
        LogPrintf("Failed to dump mempool: %s. Continuing anyway.\n", e.what());
        return false;
    }
    return true;
}

//! Guess how far we are in the verification process at the given block index
//! require cs_main if pindex has not been validated yet (because nChainTx might be unset)
double GuessVerificationProgress(const ChainTxData& data, const CBlockIndex *pindex) {
    if (pindex == nullptr)
        return 0.0;

    int64_t nNow = time(nullptr);

    double fTxTotal;

    if (pindex->nChainTx <= data.nTxCount) {
        fTxTotal = data.nTxCount + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pindex->nChainTx + (nNow - pindex->GetBlockTime()) * data.dTxRate;
    }

    return std::min<double>(pindex->nChainTx / fTxTotal, 1.0);
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // block headers
        BlockMap::iterator it1 = g_chainman.BlockIndex().begin();
        for (; it1 != g_chainman.BlockIndex().end(); it1++)
            delete (*it1).second;
        g_chainman.BlockIndex().clear();
    }
};
static CMainCleanup instance_of_cmaincleanup;

bool CoinStakeCache::GetCoinStake(const uint256 &blockHash, CTransactionRef &tx)
{
    for (const auto &i : lData) {
        if (blockHash != i.first) {
            continue;
        }
        tx = i.second;
        return true;
    }

    BlockMap::iterator mi = ::BlockIndex().find(blockHash);
    if (mi == ::BlockIndex().end()) {
        return false;
    }

    CBlockIndex *pindex = mi->second;
    if (ReadTransactionFromDiskBlock(pindex, 0, tx)) {
        return InsertCoinStake(blockHash, tx);
    }

    return false;
}

bool CoinStakeCache::InsertCoinStake(const uint256 &blockHash, const CTransactionRef &tx)
{
    lData.emplace_front(blockHash, tx);

    while (lData.size() > nMaxSize) {
        lData.pop_back();
    }

    return true;
}

Optional<uint256> ChainstateManager::SnapshotBlockhash() const {
    if (m_active_chainstate != nullptr) {
        // If a snapshot chainstate exists, it will always be our active.
        return m_active_chainstate->m_from_snapshot_blockhash;
    }
    return {};
}

std::vector<CChainState*> ChainstateManager::GetAll()
{
    std::vector<CChainState*> out;

    if (!IsSnapshotValidated() && m_ibd_chainstate) {
        out.push_back(m_ibd_chainstate.get());
    }

    if (m_snapshot_chainstate) {
        out.push_back(m_snapshot_chainstate.get());
    }

    return out;
}

CChainState& ChainstateManager::InitializeChainstate(const uint256& snapshot_blockhash)
{
    bool is_snapshot = !snapshot_blockhash.IsNull();
    std::unique_ptr<CChainState>& to_modify =
        is_snapshot ? m_snapshot_chainstate : m_ibd_chainstate;

    if (to_modify) {
        throw std::logic_error("should not be overwriting a chainstate");
    }

    to_modify.reset(new CChainState(m_blockman, snapshot_blockhash));

    // Snapshot chainstates and initial IBD chaintates always become active.
    if (is_snapshot || (!is_snapshot && !m_active_chainstate)) {
        LogPrintf("Switching active chainstate to %s\n", to_modify->ToString());
        m_active_chainstate = to_modify.get();
    } else {
        throw std::logic_error("unexpected chainstate activation");
    }

    return *to_modify;
}

CChain& ChainstateManager::ActiveChain() const
{
    assert(m_active_chainstate);
    return m_active_chainstate->m_chain;
}

bool ChainstateManager::IsSnapshotActive() const
{
    return m_snapshot_chainstate && m_active_chainstate == m_snapshot_chainstate.get();
}

CChainState& ChainstateManager::ValidatedChainstate() const
{
    if (m_snapshot_chainstate && IsSnapshotValidated()) {
        return *m_snapshot_chainstate.get();
    }
    assert(m_ibd_chainstate);
    return *m_ibd_chainstate.get();
}

bool ChainstateManager::IsBackgroundIBD(CChainState* chainstate) const
{
    return (m_snapshot_chainstate && chainstate == m_ibd_chainstate.get());
}

void ChainstateManager::Unload()
{
    for (CChainState* chainstate : this->GetAll()) {
        chainstate->m_chain.SetTip(nullptr);
        chainstate->UnloadBlockIndex();
    }

    m_blockman.Unload();
}

void ChainstateManager::Reset()
{
    m_ibd_chainstate.reset();
    m_snapshot_chainstate.reset();
    m_active_chainstate = nullptr;
    m_snapshot_validated = false;
}
