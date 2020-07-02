#include "coldrewardtracker.h"


boost::optional<CAmount> ColdRewardTracker::getBalanceInCache(const AddressType& addr)
{
    auto it = balances.find(addr);
    if (it != balances.cend()) {
        return it->second;
    } else {
        return boost::none;
    }
}

boost::optional<std::vector<BlockHeightRange>> ColdRewardTracker::getAddressRangesInCache(const AddressType& addr)
{
    auto it = addressesRanges.find(addr);
    if (it != addressesRanges.cend()) {
        return it->second;
    } else {
        return boost::none;
    }
}

boost::optional<int> ColdRewardTracker::getCheckpointInCache()
{
    return lastCheckpoint;
}

CAmount ColdRewardTracker::getBalance(const AddressType& addr)
{
    boost::optional<CAmount> balance = getBalanceInCache(addr);
    if (balance) {
        return *balance;
    }
    CAmount b = balanceGetter(addr);
    balances[addr] = b;
    return b;
}

std::vector<BlockHeightRange> ColdRewardTracker::getAddressRanges(const AddressType& addr)
{
    boost::optional<std::vector<BlockHeightRange>> ranges = getAddressRangesInCache(addr);
    if (ranges) {
        return *ranges;
    }
    std::vector<BlockHeightRange> r = rangesGetter(addr);
    if (!r.empty()) {
        addressesRanges[addr] = r;
    }
    return r;
}

int ColdRewardTracker::getCheckpoint()
{
    boost::optional<int> checkpoint = getCheckpointInCache();
    if (checkpoint) {
        return *checkpoint;
    }
    this->lastCheckpoint = checkpointGetter();
    return *this->lastCheckpoint;
}

void ColdRewardTracker::updateAddressRangesCache(const AddressType& addr, std::vector<BlockHeightRange>&& ranges)
{
    addressesRanges[addr] = ranges;
}

void ColdRewardTracker::updateCheckpointCache(int new_checkpoint)
{
    lastCheckpoint = new_checkpoint;
}

void ColdRewardTracker::AssertTrue(bool valueShouldBeTrue, const std::string& functionName, const std::string &msg)
{
    if(!valueShouldBeTrue) {
        throw std::invalid_argument(functionName + ": " + msg);
    }
}

void ColdRewardTracker::startPersistedTransaction()
{
    transactionStarter();
}

void ColdRewardTracker::endPersistedTransaction()
{
    for (auto&& p : balances) {
        balanceSetter(p.first, p.second);
    }
    for (auto&& p : addressesRanges) {
        rangesSetter(p.first, p.second);
    }
    if(lastCheckpoint) {
        checkpointSetter(*lastCheckpoint);
    }
    transactionEnder();
    addressesRanges.clear();
    balances.clear();
}

void ColdRewardTracker::revertPersistedTransaction()
{
    addressesRanges.clear();
    balances.clear();
    transactionEnder();
}

boost::optional<int> ColdRewardTracker::GetLastCheckpoint(const std::map<int, uint256> &checkpoints, int currentBlockHeight)
{
    /// retrieve the last checkpoint k, where k <= currentBlockHeight
    if(checkpoints.size() == 0) {
        return boost::none;
    }
    auto last = checkpoints.lower_bound(currentBlockHeight);
    if(last == checkpoints.end()) {
        if(checkpoints.rbegin()->first <= currentBlockHeight) {
            return checkpoints.rbegin()->first;
        }
        return boost::none;
    }
    if(last->first == currentBlockHeight) {
        return last->first;
    } else if(last != checkpoints.begin()) {
        last--;
        return last->first;
    } else {
        return boost::none;
    }
}

std::vector<ColdRewardTracker::AddressType> ColdRewardTracker::getEligibleAddresses(int currentBlockHeight)
{
    AssertTrue(currentBlockHeight % MinimumRewardRangeSpan == 0, std::string(__func__),
        "Block height should be a multiple of the reward range span");
    std::map<AddressType, std::vector<BlockHeightRange>> ranges = allRangesGetter();
    std::vector<AddressType> result;

    for(const auto& r: ranges) {
        const std::vector<BlockHeightRange>& ar = r.second;
        if(!ar.empty())
        {
            AssertTrue(ar.back().getEnd() <= currentBlockHeight, __func__, "You cannot ask for addresses eligible for rewards in the past");
            if(currentBlockHeight - ar.back().getStart() >= MinimumRewardRangeSpan && ar.back().isOverThreshold())
            {
                result.push_back(r.first);
            }
        }
    }
    return result;
}

void ColdRewardTracker::RemoveOldData(int lastCheckpoint, std::vector<BlockHeightRange>& ranges)
{
    if (ranges.size() > 0) {
        auto itr = ranges.begin();
        while (itr != ranges.end()) {
            if(itr->getStart() < lastCheckpoint && itr->getEnd() < lastCheckpoint)
                ranges.erase(itr);
            else
                ++itr;
        }
    }
}

void ColdRewardTracker::addAddressTransaction(int blockHeight, const AddressType& address, const CAmount& balanceChange, const std::map<int, uint256>& checkpoints)
{
    CAmount balance = getBalance(address) + balanceChange;
    AssertTrue(balance >= 0, __func__, "Can't apply, total address balance will be negative");
    std::vector<BlockHeightRange> ranges = getAddressRanges(address);

    const std::size_t rangesSizeBefore = ranges.size();

    balances[address] = balance;

    if (balance >= GVRThreshold) {
        if (ranges.size() == 0) {
            ranges.push_back(BlockHeightRange(blockHeight, blockHeight, true));
        } else {
            if(ranges.back().isOverThreshold()) {
                ranges.back().newEnd(blockHeight);
            } else {
                ranges.push_back(BlockHeightRange(blockHeight, blockHeight, true));
            }
        }
    } else {
        // we add a [blockHeight, blockHeight] range as a marker that the balance isn't GVR eligible anymore
        ranges.push_back(BlockHeightRange(blockHeight, blockHeight, false));
    }

    const boost::optional<int> lastBlockHeightInCheckpoint = GetLastCheckpoint(checkpoints, blockHeight);
    if(lastBlockHeightInCheckpoint) {
        RemoveOldData(*lastBlockHeightInCheckpoint, ranges);
        updateCheckpointCache(*lastBlockHeightInCheckpoint);
    }

    // ranges that are under the threshold and come at the beginning are not interesting and don't need to remain
    while(ranges.size() > 0 && !ranges[0].isOverThreshold()) {
        ranges.erase(ranges.begin());
    }

    if(ranges.size() > 0 || rangesSizeBefore > 0) {
        updateAddressRangesCache(address, std::move(ranges));
    }
}

void ColdRewardTracker::removeAddressTransaction(int blockHeight, const AddressType& address, const CAmount& balanceChangeInBlock, const std::map<int, uint256>& checkpoints)
{
    AssertTrue(getCheckpoint() < blockHeight, __func__, "Can't apply, height is lower than the last checkpoint we saw");
    CAmount balance = balanceGetter(address) - balanceChangeInBlock;
    AssertTrue(balance >= 0, __func__, "Can't apply, total address balance will be negative");
    balances[address] = balance;
    std::vector<BlockHeightRange> ranges = getAddressRanges(address);
    if (ranges.size() > 0) {
        while (!ranges.empty() && ranges.back().getEnd() == blockHeight) {
            if (ranges.back().getEnd() > ranges.back().getStart()) {
                ranges.back().newEnd(blockHeight - 1);
            } else {
                ranges.erase(ranges.end() - 1);
            }
        }
    }
    updateAddressRangesCache(address, std::move(ranges));
}

void ColdRewardTracker::setPersistedBalanceGetter(const std::function<CAmount(const AddressType&)>& func)
{
    balanceGetter = func;
}

void ColdRewardTracker::setPersistedBalanceSetter(const std::function<void(const AddressType&, const CAmount&)>& func)
{
    balanceSetter = func;
}

void ColdRewardTracker::setPersistedRangesGetter(const std::function<std::vector<BlockHeightRange>(const AddressType&)>& func)
{
    rangesGetter = func;
}

void ColdRewardTracker::setPersistedRangesSetter(const std::function<void(const AddressType&, const std::vector<BlockHeightRange>&)>& func)
{
    rangesSetter = func;
}

void ColdRewardTracker::setPersistedTransactionStarter(const std::function<void()>& func)
{
    transactionStarter = func;
}

void ColdRewardTracker::setPersisterTransactionEnder(const std::function<void()>& func)
{
    transactionEnder = func;
}

void ColdRewardTracker::setPersistedCheckpointGetter(const std::function<int()>& func)
{
    checkpointGetter = func;
}

void ColdRewardTracker::setPersistedCheckpointSetter(const std::function<void(int)>& func)
{
    checkpointSetter = func;
}

void ColdRewardTracker::setAllRangesGetter(const std::function<std::map<AddressType, std::vector<BlockHeightRange>>()>& func)
{
    allRangesGetter = func;
}

const std::map<ColdRewardTracker::AddressType, std::vector<BlockHeightRange>>& ColdRewardTracker::getAllRanges() const
{
    return addressesRanges;
}
