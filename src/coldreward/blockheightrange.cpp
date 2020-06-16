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

bool BlockHeightRange::isOverThreshold() const
{
    return overThreshold;
}

void BlockHeightRange::newEnd(const int value)
{
    end = value;
    if(start > end) {
        throw std::runtime_error("Invalid range: [" + std::to_string(start) + "," + std::to_string(end) + "]");
    }
}

BlockHeightRange::BlockHeightRange(const int Start, const int End, const bool OverThreshold) : start(Start), end(End), overThreshold(OverThreshold)
{
    if(Start > End) {
        throw std::runtime_error("Invalid range: [" + std::to_string(Start) + "," + std::to_string(End) + "]");
    }
}
