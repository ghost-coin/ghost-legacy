// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>

#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <consensus/validation.h>
#include <validation.h>
#include <chainparams.h>

#include <timedata.h>
#include <util/system.h>

// TODO remove the following dependencies
#include <chain.h>
#include <coins.h>
#include <util/moneystr.h>


#include <policy/policy.h>

// Particl dependencies
#include <blind.h>
#include <insight/balanceindex.h>


extern std::atomic_bool fBusyImporting;
extern std::atomic_bool fSkipRangeproof;

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                      && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.IsAnonInput()
            || txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    if (!tx.IsParticlVersion())
    {
        for (const auto& txin : tx.vin)
        {
            nSigOps += txin.scriptSig.GetSigOpCount(false);
        }
        for (const auto& txout : tx.vout)
        {
            nSigOps += txout.scriptPubKey.GetSigOpCount(false);
        }
    }
    for (const auto &txout : tx.vpout)
    {
        const CScript *pScriptPubKey = txout->GetPScriptPubKey();
        if (pScriptPubKey)
            nSigOps += pScriptPubKey->GetSigOpCount(false);
    };
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        if (tx.vin[i].IsAnonInput()) {
            continue;
        }

        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHashAny(tx.IsCoinStake()))
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        if (tx.vin[i].IsAnonInput()) {
            continue;
        }

        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }

    return nSigOps;
}

bool CheckValue(CValidationState &state, CAmount nValue, CAmount &nValueOut)
{
    if (nValue < 0)
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-negative");
    if (nValue > MAX_MONEY)
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-toolarge");
    nValueOut += nValue;
    return true;
}

bool CheckStandardOutput(CValidationState &state, const Consensus::Params& consensusParams, const CTxOutStandard *p, CAmount &nValueOut)
{
    if (!CheckValue(state, p->nValue, nValueOut)) {
        return false;
    }

    if (HasIsCoinstakeOp(p->scriptPubKey)) {
        if (GetAdjustedTime() < consensusParams.OpIsCoinstakeTime) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-opiscoinstake");
        }
        if (!consensusParams.fAllowOpIsCoinstakeWithP2PKH) {
            if (IsSpendScriptP2PKH(p->scriptPubKey)) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-opiscoinstake-spend-p2pkh");
            }
        }
    }

    return true;
}

bool CheckBlindOutput(CValidationState &state, const CTxOutCT *p)
{
    if (p->vData.size() < 33 || p->vData.size() > 33 + 5 + 33) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-ctout-ephem-size");
    }
    size_t nRangeProofLen = 5134;
    if (p->vRangeproof.size() < 500 || p->vRangeproof.size() > nRangeProofLen) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-ctout-rangeproof-size");
    }

    if ((fBusyImporting) && fSkipRangeproof) {
        return true;
    }

    uint64_t min_value = 0, max_value = 0;
    int rv = 0;

    if (state.fBulletproofsActive) {
        rv = secp256k1_bulletproof_rangeproof_verify(secp256k1_ctx_blind,
            blind_scratch, blind_gens, p->vRangeproof.data(), p->vRangeproof.size(),
            nullptr, &p->commitment, 1, 64, &secp256k1_generator_const_h, nullptr, 0);
    } else {
        rv = secp256k1_rangeproof_verify(secp256k1_ctx_blind, &min_value, &max_value,
            &p->commitment, p->vRangeproof.data(), p->vRangeproof.size(),
            nullptr, 0,
            secp256k1_generator_h);
    }

    if (LogAcceptCategory(BCLog::RINGCT)) {
        LogPrintf("%s: rv, min_value, max_value %d, %s, %s\n", __func__,
            rv, FormatMoney((CAmount)min_value), FormatMoney((CAmount)max_value));
    }

    if (rv != 1) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-ctout-rangeproof-verify");
    }

    return true;
}

bool CheckAnonOutput(CValidationState &state, const CTxOutRingCT *p)
{
    if (!state.rct_active) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "rctout-before-active");
    }
    if (p->vData.size() < 33 || p->vData.size() > 33 + 5 + 33) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-rctout-ephem-size");
    }

    size_t nRangeProofLen = 5134;
    if (p->vRangeproof.size() < 500 || p->vRangeproof.size() > nRangeProofLen) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-rctout-rangeproof-size");
    }

    if ((fBusyImporting) && fSkipRangeproof) {
        return true;
    }

    uint64_t min_value = 0, max_value = 0;
    int rv = 0;

    if (state.fBulletproofsActive) {
        rv = secp256k1_bulletproof_rangeproof_verify(secp256k1_ctx_blind,
            blind_scratch, blind_gens, p->vRangeproof.data(), p->vRangeproof.size(),
            nullptr, &p->commitment, 1, 64, &secp256k1_generator_const_h, nullptr, 0);
    } else {
        rv = secp256k1_rangeproof_verify(secp256k1_ctx_blind, &min_value, &max_value,
            &p->commitment, p->vRangeproof.data(), p->vRangeproof.size(),
            nullptr, 0,
            secp256k1_generator_h);
    }

    if (LogAcceptCategory(BCLog::RINGCT)) {
        LogPrintf("%s: rv, min_value, max_value %d, %s, %s\n", __func__,
            rv, FormatMoney((CAmount)min_value), FormatMoney((CAmount)max_value));
    }

    if (rv != 1) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-rctout-rangeproof-verify");
    }

    return true;
}

bool CheckDataOutput(CValidationState &state, const CTxOutData *p)
{
    if (p->vData.size() < 1) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-output-data-size");
    }

    const size_t MAX_DATA_OUTPUT_SIZE = 34 + 5 + 34; // DO_STEALTH 33, DO_STEALTH_PREFIX 4, DO_NARR_CRYPT (max 32 bytes)
    if (p->vData.size() > MAX_DATA_OUTPUT_SIZE) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-output-data-size");
    }

    return true;
}

bool CheckTransaction(const CTransaction& tx, CValidationState &state, bool fCheckDuplicateInputs)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vin-empty");

    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-oversize");

    if (tx.IsParticlVersion()) {
        const Consensus::Params& consensusParams = Params().GetConsensus();
        if (state.m_clamp_tx_version && tx.GetParticlVersion() != PARTICL_TXN_VERSION) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txn-version");
        }

        if (tx.vpout.empty()) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vpout-empty");
        }
        if (!tx.vout.empty()) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-not-empty");
        }

        size_t nStandardOutputs = 0, nDataOutputs = 0, nBlindOutputs = 0, nAnonOutputs = 0;
        CAmount nValueOut = 0;
        for (const auto &txout : tx.vpout) {
            switch (txout->nVersion) {
                case OUTPUT_STANDARD:
                    if (!CheckStandardOutput(state, consensusParams, (CTxOutStandard*) txout.get(), nValueOut)) {
                        return false;
                    }
                    nStandardOutputs++;
                    break;
                case OUTPUT_CT:
                    if (!CheckBlindOutput(state, (CTxOutCT*) txout.get())) {
                        return false;
                    }
                    nBlindOutputs++;
                    break;
                case OUTPUT_RINGCT:
                    if (!CheckAnonOutput(state, (CTxOutRingCT*) txout.get())) {
                        return false;
                    }
                    nAnonOutputs++;
                    break;
                case OUTPUT_DATA:
                    if (!CheckDataOutput(state, (CTxOutData*) txout.get())) {
                        return false;
                    }
                    nDataOutputs++;
                    break;
                default:
                    return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-unknown-output-version");
            }

            if (!MoneyRange(nValueOut)) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
            }
        }

        size_t max_data_outputs = 1 + nStandardOutputs; // extra 1 for ct fee output
        if (state.m_clamp_tx_version) {
            max_data_outputs += nBlindOutputs + nAnonOutputs;
        }
        if (nDataOutputs > max_data_outputs) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "too-many-data-outputs");
        }
    } else {
        if (fParticlMode) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txn-version");
        }
        if (tx.vout.empty()) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-empty");
        }

        // Check for negative or overflow output values
        CAmount nValueOut = 0;
        for (const auto& txout : tx.vout)
        {
            if (txout.nValue < 0)
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-negative");
            if (txout.nValue > MAX_MONEY)
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-vout-toolarge");
            nValueOut += txout.nValue;
            if (!MoneyRange(nValueOut))
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
        }
    }

    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
    if (fCheckDuplicateInputs) {
        std::set<COutPoint> vInOutPoints;
        for (const auto& txin : tx.vin)
        {
            if (!txin.IsAnonInput()
                && !vInOutPoints.insert(txin.prevout).second) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
            }
        }
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-cb-length");
    } else {
        for (const auto& txin : tx.vin) {
            if (!txin.IsAnonInput() && txin.prevout.IsNull()) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-prevout-null");
            }
        }
    }

    return true;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee)
{
    // Reset per tx
    state.fHasAnonOutput = false;
    state.fHasAnonInput = false;
    state.m_spends_frozen_blinded = false;
    state.m_setHaveKI.clear();  // Pass keyimages through state to add to db
    bool spends_tainted_blinded = false;  // If true limit max plain output
    bool spends_post_fork_blinded = false;

    const Consensus::Params& consensusParams = ::Params().GetConsensus();
    size_t min_ring_size = consensusParams.m_max_ringsize;
    size_t max_ring_size = consensusParams.m_min_ringsize;

    bool is_particl_tx = tx.IsParticlVersion();
    if (is_particl_tx && tx.vin.size() < 1) { // early out
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txn-no-inputs",
                         strprintf("%s: no inputs", __func__));
    }

    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(ValidationInvalidReason::TX_MISSING_INPUTS, false, REJECT_INVALID, "bad-txns-inputs-missingorspent",
                         strprintf("%s: inputs missing/spent", __func__));
    }

    std::vector<const secp256k1_pedersen_commitment*> vpCommitsIn, vpCommitsOut;
    size_t nStandard = 0, nCt = 0, nRingCTInputs = 0, nRCTPrevouts = 0;
    CAmount nValueIn = 0;
    CAmount nFees = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        if (tx.vin[i].IsAnonInput()) {
            state.fHasAnonInput = true;
            nRingCTInputs++;

            const std::vector<uint8_t> &vKeyImages = tx.vin[i].scriptData.stack[0];
            const std::vector<uint8_t> &vMI = tx.vin[i].scriptWitness.stack[0];
            uint32_t nInputs, nRingSize;
            tx.vin[i].GetAnonInfo(nInputs, nRingSize);
            if (nInputs < 1 || nInputs > consensusParams.m_max_anon_inputs) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-anon-num-inputs");
            }
            if (nRingSize < consensusParams.m_min_ringsize || nRingSize > consensusParams.m_max_ringsize) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-anon-ringsize");
            }
            if (min_ring_size > nRingSize) {
                min_ring_size = nRingSize;
            }
            if (max_ring_size < nRingSize) {
                max_ring_size = nRingSize;
            }

            size_t ofs = 0, nB = 0;
            for (size_t k = 0; k < nInputs; ++k) {
                const CCmpPubKey &ki = *((CCmpPubKey*)&vKeyImages[k*33]);
                if (!state.m_setHaveKI.insert(ki).second) {
                    if (LogAcceptCategory(BCLog::RINGCT)) {
                        LogPrintf("%s: Duplicate keyimage detected in txn %s.\n", __func__,
                            HexStr(ki.begin(), ki.end()));
                    }
                    return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-anonin-dup-ki");
                }
                for (size_t i = 0; i < nRingSize; ++i) {
                    nRCTPrevouts++;
                    int64_t nIndex = 0;
                    if (0 != GetVarInt(vMI, ofs, (uint64_t&)nIndex, nB)) {
                        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-anonin-extract-i");
                    }
                    ofs += nB;
                    if (nIndex <= consensusParams.m_frozen_anon_index) {
                        state.m_spends_frozen_blinded = true;
                        if (!IsWhitelistedAnonOutput(nIndex)) {
                            spends_tainted_blinded = true;
                        }
                        if (IsBlacklistedAnonOutput(nIndex)) {
                            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-frozen-blinded-blacklisted");
                        }
                    } else {
                        spends_post_fork_blinded = true;
                    }
                }
            }
            continue;
        }

        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase or coinstake, check that it's matured
        if (coin.IsCoinBase())
        {
            if (nSpendHeight - coin.nHeight < COINBASE_MATURITY)
            {
                if (is_particl_tx) {
                    // Scale in the depth restriction to start the chain
                    int nRequiredDepth = std::min(COINBASE_MATURITY, (int)(coin.nHeight / 2));
                    if (nSpendHeight - coin.nHeight < nRequiredDepth) {
                        return state.Invalid(ValidationInvalidReason::TX_PREMATURE_SPEND, false,
                            REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                            strprintf("tried to spend coinbase at height %d at depth %d, required %d", coin.nHeight, nSpendHeight - coin.nHeight, nRequiredDepth));
                    }
                } else
                return state.Invalid(ValidationInvalidReason::TX_PREMATURE_SPEND, false, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                    strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
            }
        }

        // Check for negative or overflow input values
        if (is_particl_tx) {
            if (coin.nType == OUTPUT_STANDARD) {
                nValueIn += coin.out.nValue;
                if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
                    return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
                }
                nStandard++;
            } else
            if (coin.nType == OUTPUT_CT) {
                vpCommitsIn.push_back(&coin.commitment);
                nCt++;

                if (coin.nHeight <= consensusParams.m_frozen_blinded_height) {
                    state.m_spends_frozen_blinded = true;
                    if (IsFrozenBlindOutput(prevout.hash)) {
                        spends_tainted_blinded = true;
                    }
                } else {
                    spends_post_fork_blinded = true;
                }
            } else {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-input-type");
            }
        } else {
            nValueIn += coin.out.nValue;
            if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
            }
        }
    }

    if (state.m_exploit_fix_2) {
        if (state.m_spends_frozen_blinded && spends_post_fork_blinded) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "mixed-frozen-blinded");
        }
        if (state.m_spends_frozen_blinded && max_ring_size > 1) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-frozen-ringsize");
        }
    }
    if (spends_post_fork_blinded && min_ring_size < consensusParams.m_min_ringsize_post_hf2) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-anon-ringsize");
    }
    if ((nStandard > 0) + (nCt > 0) + (nRingCTInputs > 0) > 1) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "mixed-input-types");
    }

    size_t nCTInputs = nCt, nCTOutputs = 0, nRingCTOutputs = 0;
    // GetPlainValueOut adds to nStandard, nCt, nRingCT
    CAmount nPlainValueOut = tx.GetPlainValueOut(nStandard, nCTOutputs, nRingCTOutputs);
    nCt += nCTOutputs;
    state.fHasAnonOutput = nRingCTOutputs > 0;

    txfee = 0;
    if (is_particl_tx) {
        if (!tx.IsCoinStake()) {
            // Tally transaction fees
            if (nCt > 0 || nRingCTOutputs > 0 || nRingCTInputs > 0) {
                if (!tx.GetCTFee(txfee)) {
                    return state.Invalid(ValidationInvalidReason::CONSENSUS, error("%s: bad-fee-output", __func__), REJECT_INVALID, "bad-fee-output");
                }
            } else {
                txfee = nValueIn - nPlainValueOut;

                if (nValueIn < nPlainValueOut) {
                    return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-in-belowout",
                        strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(nPlainValueOut)));
                }
            }

            if (txfee < 0) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-fee-negative");
            }
            nFees += txfee;
            if (!MoneyRange(nFees)) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-fee-outofrange");
            }

            // Enforce smsg fees
            CAmount nTotalMsgFees = tx.GetTotalSMSGFees();
            if (nTotalMsgFees > 0) {
                size_t nTxBytes = GetVirtualTransactionSize(tx);
                CFeeRate fundingTxnFeeRate = CFeeRate(consensusParams.smsg_fee_funding_tx_per_k);
                CAmount nTotalExpectedFees = nTotalMsgFees + fundingTxnFeeRate.GetFee(nTxBytes);

                if (txfee < nTotalExpectedFees) {
                    if (state.fEnforceSmsgFees) {
                        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-fee-smsg",
                            strprintf("fees (%s) < expected (%s)", FormatMoney(txfee), FormatMoney(nTotalExpectedFees)));
                    } else {
                        LogPrintf("%s: bad-txns-fee-smsg, %d expected %d, not enforcing.\n", __func__, txfee, nTotalExpectedFees);
                    }
                }
            }
        } else {
            // Return block reward in txfee
            txfee = nPlainValueOut - nValueIn;
            if (nCt > 0 || nRingCTOutputs > 0 || nRingCTInputs > 0) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, error("%s: non-standard elements in coinstake", __func__),
                    REJECT_INVALID, "bad-coinstake-output");
            }
        }
    } else {
        if (nValueIn < tx.GetValueOut()) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-in-belowout",
                strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(tx.GetValueOut())));
        }

        // Tally transaction fees
        txfee = nValueIn - tx.GetValueOut();
        nFees += txfee;
        if (!MoneyRange(nFees)) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-fee-outofrange");
        }
    }

    if (state.m_exploit_fix_2 && state.m_spends_frozen_blinded) {
        if (nRingCTOutputs > 0 || nCTOutputs > 0) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-frozen-blinded-out");
        }
        if (spends_tainted_blinded && nPlainValueOut + txfee > consensusParams.m_max_tainted_value_out) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-frozen-blinded-too-large");
        }
        /* TODO? Limit to spending one frozen output at a time
        if (tx.vin.size() > 1 || nRCTPrevouts > 1) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-frozen-multiple-inputs");
        }
        */
    }

    // Track blinded balances
    state.tx_balances[BAL_IND_PLAIN_ADDED] = nPlainValueOut;
    state.tx_balances[BAL_IND_PLAIN_REMOVED] = nValueIn;
    if (!state.m_exploit_fix_2 || !state.m_spends_frozen_blinded) {
        if (nRingCTInputs > 0) { // spending anon
            state.tx_balances[BAL_IND_ANON_REMOVED] = nPlainValueOut + txfee;
        } else
        if (nCTInputs > 0) { // spending blind
            state.tx_balances[BAL_IND_BLIND_REMOVED] = nPlainValueOut + txfee;
        }
    }
    if (nRingCTOutputs > 0 && nValueIn > 0) {
        state.tx_balances[BAL_IND_ANON_ADDED] = nValueIn - (nPlainValueOut + txfee);
    }
    if (nCTOutputs > 0 && nValueIn > 0) {
        state.tx_balances[BAL_IND_BLIND_ADDED] = nValueIn - (nPlainValueOut + txfee);
    }
    if (state.m_clamp_tx_version && nValueIn > 0 && nRingCTOutputs > 0 && nCTOutputs > 0) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-plain-in-mixed-out");
    }

    if ((nCt > 0 || nRingCTOutputs > 0) && nRingCTInputs == 0) {
        bool default_accept_anon = state.m_exploit_fix_2 ? true : DEFAULT_ACCEPT_ANON_TX;
        bool default_accept_blind = state.m_exploit_fix_2 ? true : DEFAULT_ACCEPT_BLIND_TX;
        if (state.m_exploit_fix_1 &&
            nRingCTOutputs > 0 &&
            !gArgs.GetBoolArg("-acceptanontxn", default_accept_anon)) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-anon-disabled");
        }
        if (state.m_exploit_fix_1 &&
            nCt > 0 &&
            !gArgs.GetBoolArg("-acceptblindtxn", default_accept_blind)) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-blind-disabled");
        }
        if (!state.m_exploit_fix_1 && nCt == 0) {
            return true;
        }

        nPlainValueOut += txfee;
        if (!MoneyRange(nPlainValueOut)) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-out-outofrange");
        }
        if (!MoneyRange(nValueIn)) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
        }

        // Commitments must sum to 0
        secp256k1_pedersen_commitment plainInCommitment, plainOutCommitment;
        uint8_t blindPlain[32] = {0};
        if (nValueIn > 0) {
            if (!secp256k1_pedersen_commit(secp256k1_ctx_blind, &plainInCommitment, blindPlain, (uint64_t) nValueIn, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "commit-failed");
            }
            vpCommitsIn.push_back(&plainInCommitment);
        }

        if (nPlainValueOut > 0) {
            if (state.m_exploit_fix_2 && state.m_spends_frozen_blinded) {
                // Get the blinding factor from the fee data output
                const std::vector<uint8_t> &vData = *tx.vpout[0]->GetPData();
                size_t nb = 0;
                uint64_t nTmp;
                if (0 != GetVarInt(vData, 1, nTmp, nb) || vData.size() < 1 + nb + 33 || vData[1 + nb] != DO_MASK) {
                    return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-txns-frozen-bf");
                }
                memcpy(blindPlain, &vData[1 + nb + 1], 32);
            }
            if (!secp256k1_pedersen_commit(secp256k1_ctx_blind, &plainOutCommitment, blindPlain, (uint64_t) nPlainValueOut, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
                return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "commit-failed");
            }
            vpCommitsOut.push_back(&plainOutCommitment);
        }

        secp256k1_pedersen_commitment *pc;
        for (auto &txout : tx.vpout) {
            if ((pc = txout->GetPCommitment())) {
                vpCommitsOut.push_back(pc);
            }
        }

        int rv = secp256k1_pedersen_verify_tally(secp256k1_ctx_blind,
            vpCommitsIn.data(), vpCommitsIn.size(), vpCommitsOut.data(), vpCommitsOut.size());

        if (rv != 1) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-commitment-sum");
        }
    }

    return true;
}
