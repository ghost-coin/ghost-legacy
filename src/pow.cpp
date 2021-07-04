// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int LwmaCalculateNextWorkRequired(const CBlockIndex* pindexPrev, const CBlockHeader *pblock)
{
    const Consensus::Params &params = Params().GetConsensus();

    // This cannot handle the genesis block and early blocks in general.
    assert(pindexPrev);

    // Special difficulty rule for testnet:
    // If the new block's timestamp is more than 2* 10 minutes then allow
    // mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks &&
        (pblock->GetBlockTime() >
         pindexPrev->GetBlockTime() + 10 * Params().GetTargetSpacing())) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    const int nHeight = pindexPrev->nHeight + 1;

    // Don't adjust difficult until we have a full window worth
    // this means we should also start the starting value
    // to a reasonable level !
    if (nHeight <= params.nZawyLwmaAveragingWindow) {
      return UintToArith256(params.powLimit).GetCompact();
    }

    const int64_t T = Params().GetTargetSpacing();
    const int N = params.nZawyLwmaAveragingWindow;
    const int k = (N+1) * T / 2;  // ignore adjust 0.9989^(500/N) from python code
    const int dnorm = 10;

    arith_uint256 sum_target;
    int t = 0, j = 0;

    // Loop through N most recent blocks.
    for (int i = nHeight - N; i < nHeight; i++) {
        const CBlockIndex* block = pindexPrev->GetAncestor(i);
        const CBlockIndex* block_Prev = block->GetAncestor(i - 1);
        int64_t solvetime = block->GetBlockTime() - block_Prev->GetBlockTime();

        solvetime = std::min(6*T, solvetime);

        j++;
        t += solvetime * j;  // Weighted solvetime sum.

        // Target sum divided by a factor, (k N^2).
        // The factor is a part of the final equation. However we divide sum_target here to avoid
        // potential overflow.
        arith_uint256 target;
        target.SetCompact(block->nBits);
        sum_target += target / (k * N * N);
    }
    // Keep t reasonable in case strange solvetimes occurred.
    if (t < N * k / dnorm) {
        t = N * k / dnorm;
    }

    const arith_uint256 pow_limit = UintToArith256(params.powLimit);
    arith_uint256 next_target = t * sum_target;
    if (next_target > pow_limit) {
        next_target = pow_limit;
    }

    return next_target.GetCompact();
}

unsigned int GetNextWorkRequiredPoS(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const CChainParams& params)
{
    arith_uint256 bnProofOfWorkLimit;
    unsigned int nProofOfWorkLimit;
    int nHeight = pindexLast ? pindexLast->nHeight+1 : 0;

    if (nHeight < (int)params.GetLastImportHeight()) {
        if (nHeight == 0) {
            return arith_uint256("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").GetCompact();
        }
        int nLastImportHeight = (int)params.GetLastImportHeight();
        arith_uint256 nMaxProofOfWorkLimit = arith_uint256("000000000008ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        arith_uint256 nMinProofOfWorkLimit = UintToArith256(params.GetConsensus().powLimit);
        arith_uint256 nStep = (nMaxProofOfWorkLimit - nMinProofOfWorkLimit) / nLastImportHeight;

        bnProofOfWorkLimit = nMaxProofOfWorkLimit - (nStep * nHeight);
        nProofOfWorkLimit = bnProofOfWorkLimit.GetCompact();
    } else {
        bnProofOfWorkLimit = UintToArith256(params.GetConsensus().powLimit);
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

    int64_t nTargetSpacing = params.GetTargetSpacing();
    int64_t nTargetTimespan = params.GetTargetTimespan();
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

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const CChainParams& chainparams = Params();
    if (pindexLast->nHeight + 1 >= params.nLWMADiffUpgradeHeight) {
        return LwmaCalculateNextWorkRequired(pindexLast, pblock);
    }
    return GetNextWorkRequiredPoS(pindexLast, pblock, chainparams);
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params,
    int nBlockHeight, int nLastImportHeight)
{
    arith_uint256 bnProofOfWorkLimit;
    if (nBlockHeight < nLastImportHeight)
    {
        arith_uint256 nMinProofOfWorkLimit = arith_uint256("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        bnProofOfWorkLimit = nMinProofOfWorkLimit;
    } else
    {
        bnProofOfWorkLimit = UintToArith256(params.powLimit);
    };
    
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > bnProofOfWorkLimit)
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
