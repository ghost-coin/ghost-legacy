#include "blockheightrange.h"

#include <stdexcept>

int BlockHeightRange::getEnd() const
{
    return end;
}

int BlockHeightRange::getStart() const
{
    return start;
}

unsigned BlockHeightRange::getRewardMultiplier() const
{
    return rewardMultiplier;
}

void BlockHeightRange::newEnd(const int value)
{
    end = value;
    if(start > end) {
        throw std::runtime_error("Invalid range: [" + std::to_string(start) + "," + std::to_string(end) + "]");
    }
}

BlockHeightRange::BlockHeightRange(const int Start, const int End, const unsigned RewardMultiplier) : start(Start), end(End), rewardMultiplier(RewardMultiplier)
{
    if(Start > End) {
        throw std::runtime_error("Invalid range: [" + std::to_string(Start) + "," + std::to_string(End) + "]");
    }
}
