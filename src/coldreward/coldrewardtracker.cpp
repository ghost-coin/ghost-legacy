#include "coldrewardtracker.h"

CAmount ColdRewardTracker::GVRThreshold = 20000 * COIN;
int ColdRewardTracker::MinimumRewardRangeSpan = 30 * 24 * 30;


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

unsigned ColdRewardTracker::ExtractRewardMultiplierFromRanges(int currentBlockHeight, const std::vector<BlockHeightRange>& addressRanges)
{
    AssertTrue(currentBlockHeight % MinimumRewardRangeSpan == 0, std::string(__func__),
        "Block height should be a multiple of the reward range span");

    std::vector<unsigned> rewardMultipliers;

    const auto& ar = addressRanges;

    for(unsigned i = 0; i < ar.size(); i++) {
        const unsigned idx = ar.size() - i - 1;
        AssertTrue(currentBlockHeight > ar[idx].getStart(), std::string(__func__), "You can't get the reward for the past");
        AssertTrue(currentBlockHeight > ar[idx].getEnd(), std::string(__func__), "You can't get the reward for the past");

        // collect all reward multipliers that are > 0 over the last periods, to figure out the final reward
        const int startDistance = currentBlockHeight - ar[idx].getStart();
        const int endDistance = currentBlockHeight -   ar[idx].getEnd();
        if(ar[idx].getRewardMultiplier() > 0) {

            // collect all changes in balance over the last MinimumRewardRangeSpan

            if(startDistance == MinimumRewardRangeSpan) {
                // if the balance changed at the point of start
                rewardMultipliers.push_back(ar[idx].getRewardMultiplier());
            } else if(startDistance < MinimumRewardRangeSpan || endDistance < MinimumRewardRangeSpan) {
                // if start or end are within this reward range
                if(startDistance >= MinimumRewardRangeSpan) {
                    // start is before the minimum range; i.e., the current reward counts
                    rewardMultipliers.push_back(ar[idx].getRewardMultiplier());
                } else {
                    // start is within the minimum range; i.e., the previous reward counts
                    rewardMultipliers.push_back(std::min(ar[idx].getPrevRewardMultiplier(), ar[idx].getRewardMultiplier()));
                }
            } else if (rewardMultipliers.empty()) {
                // we reach this point if no transaction was every done within this span. The reward is decided based on the last multiplier available
                rewardMultipliers.push_back(ar[idx].getRewardMultiplier());
                break;
            }
        } else {
            if(startDistance <= MinimumRewardRangeSpan || endDistance <= MinimumRewardRangeSpan) {
                // if any multiplier is zero during the last MinimumRewardSpan, then no reward
                rewardMultipliers.clear();
            }
            break;
        }
    }

    if(rewardMultipliers.empty()) {
        return 0;
    } else {
        return *std::min_element(rewardMultipliers.cbegin(), rewardMultipliers.cend());
    }
}

std::vector<std::pair<ColdRewardTracker::AddressType, unsigned>> ColdRewardTracker::getEligibleAddresses(int currentBlockHeight)
{
    AssertTrue(currentBlockHeight % MinimumRewardRangeSpan == 0, std::string(__func__),
        "Block height should be a multiple of the reward range span");
    const std::map<AddressType, std::vector<BlockHeightRange>> ranges = allRangesGetter();
    std::vector<std::pair<AddressType, unsigned>> result;

    for(const auto& r: ranges) {
        const std::vector<BlockHeightRange>& ar = r.second;
        AssertTrue(ar.empty() || ar.back().getEnd() <= currentBlockHeight, __func__, "You cannot ask for addresses eligible for rewards in the past");
        const unsigned rewardMultiplier = ExtractRewardMultiplierFromRanges(currentBlockHeight, ar);
        if(rewardMultiplier > 0)
        {
            // over the range of the last MinimumRewardRangeSpan, the minimum multiplier determines the reward
            // Example: if over the last (month=MinimumRewardRangeSpan, and GVRThreshold=20k),
            // the balance goes below 40k, but remains over 20k, the max multiplier is 2 and minimum is 1, and the reward
            // multiplier is 1
            result.push_back(std::make_pair(r.first, rewardMultiplier));
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
    const CAmount balance = getBalance(address) + balanceChange;
    AssertTrue(balance >= 0, __func__, "Can't apply, total address balance will be negative");
    std::vector<BlockHeightRange> ranges = getAddressRanges(address);

    const std::size_t rangesSizeBefore = ranges.size();

    balances[address] = balance;

    {
        const unsigned currentMultiplier = static_cast<unsigned>(balance / GVRThreshold);
        if (ranges.size() == 0) {
            ranges.push_back(BlockHeightRange(blockHeight, blockHeight, currentMultiplier, 0));
        } else if(ranges.back().getRewardMultiplier() != currentMultiplier) {
            // we add a [blockHeight, blockHeight] range as a marker that the balance has crossed a threshold multiple
            ranges.push_back(BlockHeightRange(blockHeight, blockHeight, currentMultiplier, ranges.back().getRewardMultiplier()));
        } else {
            ranges.back().newEnd(blockHeight);
        }
    }

    const boost::optional<int> lastBlockHeightInCheckpoint = GetLastCheckpoint(checkpoints, blockHeight);
    if(lastBlockHeightInCheckpoint) {
        RemoveOldData(*lastBlockHeightInCheckpoint, ranges);
        updateCheckpointCache(*lastBlockHeightInCheckpoint);
    }

    // ranges that are under the threshold and come at the beginning are not interesting and don't need to remain
    while(ranges.size() > 0 && ranges[0].getRewardMultiplier() == 0) {
        ranges.erase(ranges.begin());
    }

    if(ranges.size() > 0 || rangesSizeBefore > 0) {
        updateAddressRangesCache(address, std::move(ranges));
    }
}

void ColdRewardTracker::removeAddressTransaction(int blockHeight, const AddressType& address, const CAmount& balanceChangeInBlock)
{
    const int lastCheckpointSeen = getCheckpoint();
    AssertTrue(lastCheckpointSeen < blockHeight, __func__, "Can't apply, height (" + std::to_string(blockHeight) +
                                                            ") is lower than the last checkpoint seen (" + std::to_string(lastCheckpointSeen) + ")");
    const CAmount balance = balanceGetter(address) - balanceChangeInBlock;
    AssertTrue(balance >= 0, __func__, "Can't apply, total address balance will be negative");
    balances[address] = balance;
    std::vector<BlockHeightRange> ranges = getAddressRanges(address);

    AssertTrue(ranges.empty() || ranges.back().getEnd() <= blockHeight, __func__, "Can't rollback blocks in the past before rolling back thr ones that come after them");

    while (!ranges.empty() && ranges.back().getEnd() == blockHeight) {
        if (ranges.back().getEnd() > ranges.back().getStart()) {
            ranges.back().newEnd(blockHeight - 1);
        } else {
            ranges.erase(ranges.end() - 1);
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
