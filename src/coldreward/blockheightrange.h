#ifndef BLOCKHEIGHTRANGE_H
#define BLOCKHEIGHTRANGE_H

#include "amount.h"

class BlockHeightRange
{
    /// start and end of the range
    int start = 0;
    int end = 0;

    /// how many multiples of the minimum amount for a GVR requirement this range has
    unsigned rewardMultiplier = 0;
    unsigned prevMultiplier = 0;

public:
    BlockHeightRange(int Start, int End, unsigned RewardMultiplier, unsigned PrevRewardMultiplier);

    int getEnd() const;
    int getStart() const;
    unsigned getRewardMultiplier() const;
    unsigned getPrevRewardMultiplier() const;
    void newEnd(int value);
};

#endif // BLOCKHEIGHTRANGE_H
