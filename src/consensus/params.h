// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>
#include <limits>
#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;

    int nSubsidyHalvingInterval;
    /* Block hash that is excepted from BIP16 enforcement */
    uint256 BIP16Exception;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;

    /** Time at which OP_ISCOINSTAKE becomes active */
    int64_t OpIsCoinstakeTime;
    bool fAllowOpIsCoinstakeWithP2PKH;
    /** Time at which Paid SMSG becomes active */
    uint32_t nPaidSmsgTime;
    /** Time at which csp2sh becomes active */
    uint32_t csp2shTime;
    /** Time at which variable SMSG fee become active */
    uint32_t smsg_fee_time;
    /** Time at which bulletproofs become active */
    uint32_t bulletproof_time;
    /** Time at which RCT become active */
    uint32_t rct_time;
    /** Time at which SMSG difficulty tokens are enforced */
    uint32_t smsg_difficulty_time;
    /** Time of fork to clamp tx version, fix moneysupply and add more data outputs for blind and anon txns */
    uint32_t clamp_tx_version_time = 0xffffffff;
    /** Exploit fix 1 */
    uint32_t exploit_fix_1_time = 0;
    /** Exploit fix 2 */
    uint32_t exploit_fix_2_time = 0xffffffff;
    int64_t m_frozen_anon_index = 0; // Last prefork anonoutput index
    int m_frozen_blinded_height = 0;
    int64_t m_max_tainted_value_out = 200LL * 100000000LL /* COIN */;  // Maximum value of tainted blinded output that can be spent without being whitelisted

    /** Avoid circular dependency */
    size_t m_min_ringsize_post_hf2 = 3;
    size_t m_min_ringsize = 1;
    size_t m_max_ringsize = 32;
    size_t m_max_anon_inputs = 32;

    uint32_t smsg_fee_period;
    int64_t smsg_fee_funding_tx_per_k;
    int64_t smsg_fee_msg_per_day_per_k;
    int64_t smsg_fee_max_delta_percent; /* Divided by 1000000 */
    uint32_t smsg_min_difficulty;
    uint32_t smsg_difficulty_max_delta;

    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;

    int nMinRCTOutputDepth;
    //increase blockreward to match expected supply inflation
    int nBlockRewardIncreaseHeight;
    //GVR Allocation one time payout params
    int nOneTimeGVRPayHeight;
    int64_t nGVRPayOnetimeAmt;
    // Params for Zawy's LWMA difficulty adjustment algorithm.
    int64_t nZawyLwmaAveragingWindow;
    int nLWMADiffUpgradeHeight;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
