#ifndef BLOCKHEIGHTRANGE_H
#define BLOCKHEIGHTRANGE_H

#include "amount.h"

class BlockHeightRange
{
    int start = 0;
    int end = 0;
    bool overThreshold = false;

public:
    BlockHeightRange(int Start, int End, bool OverThreshold);

    int getEnd() const;
    int getStart() const;
    bool isOverThreshold() const;
    void newEnd(int value);
};

#endif // BLOCKHEIGHTRANGE_H
