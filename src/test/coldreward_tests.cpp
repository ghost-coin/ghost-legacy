// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <streams.h>
#include <test/setup_common.h>
#include <uint256.h>
#include <version.h>

#include <boost/test/unit_test.hpp>
#include <iomanip>
#include <sstream>
#include <string>

#include "coldreward/coldrewardtracker.h"

struct ColdRewardsSetup : public BasicTestingSetup {
    explicit ColdRewardsSetup()
    {
        std::function<CAmount(const AddressType&)> balanceGetter = [this](const AddressType& addr) {
            auto it = balances.find(addr);
            return it == balances.cend() ? 0 : it->second;
        };
        std::function<void(const AddressType&, const CAmount&)> balanceSetter = [this](const AddressType& addr, const CAmount& amount) {
            balances[addr] = amount;
        };

        std::function<std::vector<BlockHeightRange>(const AddressType&)> rangesGetter = [this](const AddressType& addr) {
            auto it = ranges.find(addr);
            return it == ranges.cend() ? std::vector<BlockHeightRange>() : it->second;
        };
        std::function<void(const AddressType&, const std::vector<BlockHeightRange>&)> rangesSetter = [this](const AddressType& Addr, const std::vector<BlockHeightRange>& Ranges) {
            ranges[Addr] = Ranges;
        };

        std::function<void()> transactionStarter = []() {};
        std::function<void()> transactionEnder = []() {};

        std::function<std::map<AddressType, std::vector<BlockHeightRange>>()> allRangesGetter = [this]() {
            return ranges;
        };

        tracker.setPersistedRangesGetter(rangesGetter);
        tracker.setPersistedRangesSetter(rangesSetter);
        tracker.setPersistedBalanceGetter(balanceGetter);
        tracker.setPersistedBalanceSetter(balanceSetter);
        tracker.setPersistedTransactionStarter(transactionStarter);
        tracker.setPersisterTransactionEnder(transactionEnder);
        tracker.setAllRangesGetter(allRangesGetter);
    }

    ~ColdRewardsSetup()
    {
    }

    ColdRewardTracker tracker;
    using AddressType = ColdRewardTracker::AddressType;

    // we use these to simulate database storage
    std::map<AddressType, CAmount> balances;
    std::map<AddressType, std::vector<BlockHeightRange>> ranges;
    std::map<int, uint256> checkpoints;
};

namespace {
ColdRewardTracker::AddressType VecUint8FromString(const std::string& str)
{
    return ColdRewardTracker::AddressType(str.cbegin(), str.cend());
}
std::string StringFromVecUint8(const ColdRewardTracker::AddressType vec)
{
    return std::string(vec.cbegin(), vec.cend());
}
} // namespace


BOOST_FIXTURE_TEST_SUITE(coldreward_tests, ColdRewardsSetup)

BOOST_AUTO_TEST_CASE(basic)
{
    std::string addrStr = "abc";
    AddressType addr = VecUint8FromString(addrStr);

    // 10 coins added at block 50
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(50, addr, 10 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // balance changes with no range changes, because nothing exceeded 20k
    BOOST_CHECK_EQUAL(balances.at(addr), 10 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 0);

    // add 20k coins at block 51
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(51, addr, 20000 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // now we have one new range entry + balance update
    BOOST_CHECK_EQUAL(balances.at(addr), 20010 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 51);

    // subtract 5 coins at block 52
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(52, addr, -5 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // now that range entry got extended becasue we're still over 20k
    BOOST_CHECK_EQUAL(balances.at(addr), 20005 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 52);

    // subtract 5 coins at block 100
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(100, addr, -5 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // we're still equal or over 20k, so the range is extended
    BOOST_CHECK_EQUAL(balances.at(addr), 20000 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 100);

    // subtract 5 coins at block 110
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(110, addr, -5 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // now we're below 20k, we get a new range at the end [110,110] to show the break up
    BOOST_CHECK_EQUAL(balances.at(addr), 19995 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 100);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getStart(), 110);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getEnd(), 110);

    // at block 21600 and 2*21600 (after 1 and 2 months), no one is eligible for a reward
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 0);

    // revert block 110, now we're back 20k+
    tracker.startPersistedTransaction();
    tracker.removeAddressTransaction(110, addr, -5 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // we're eligible for a reward only the second month
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 1);
    BOOST_CHECK(tracker.getEligibleAddresses(2 * 21600)[0] == addr);

    // we're back to the previous state
    BOOST_CHECK_EQUAL(balances.at(addr), 20000 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 100);

    // subtract 5 coins at block 101
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(101, addr, -5 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // now we're below 20k again
    BOOST_CHECK_EQUAL(balances.at(addr), 19995 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 100);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getStart(), 101);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getEnd(), 101);

    // at block 21600 and 2*21600 (after 1 and 2 months), no one is eligible for a reward
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 0);

    // now revert that last block
    tracker.startPersistedTransaction();
    tracker.removeAddressTransaction(101, addr, -5 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // we're eligible for a reward only the second month
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 1);
    BOOST_CHECK(tracker.getEligibleAddresses(2 * 21600)[0] == addr);

    // we're back to the previous state
    BOOST_CHECK_EQUAL(balances.at(addr), 20000 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 100);

    // again, we're eligible for a reward only the second month
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 1);
    BOOST_CHECK(tracker.getEligibleAddresses(2 * 21600)[0] == addr);

    // now we revert one more hypothetical block (this is unrealistic, just for tests)
    // to see that we go back to 99 from 100
    // (even though it wasn't added, but it's still logically valid,
    //  since the user owned a 20k+ balance from block 50 to 99)
    tracker.startPersistedTransaction();
    tracker.removeAddressTransaction(100, addr, 0 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // we're eligible for a reward only the second month
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 1);
    BOOST_CHECK(tracker.getEligibleAddresses(2 * 21600)[0] == addr);

    // we're back to the previous state
    BOOST_CHECK_EQUAL(balances.at(addr), 20000 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 99);

    // again, we're eligible for a reward only the second month
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 1);
    BOOST_CHECK(tracker.getEligibleAddresses(2 * 21600)[0] == addr);

    // subtract 5 coins at block 101, again
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(101, addr, -5 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // now we're below 20k again
    BOOST_CHECK_EQUAL(balances.at(addr), 19995 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 99);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getStart(), 101);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getEnd(), 101);

    // at block 21600 and 2*21600 (after 1 and 2 months), no one is eligible for a reward
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 0);

}
BOOST_AUTO_TEST_CASE(corner)
{
    std::string addrStr = "abc";
    AddressType addr = VecUint8FromString(addrStr);

    // 20k coins added at block 10
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(10, addr, 20000 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr), 20000 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 10);

    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);

    // 5 more added to create range at block 21599 which is 1 block below the end of the first month
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(21599, addr, 5 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr), 20005 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 21599);

    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 1);

    // add 5 more
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(21600, addr, 5 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr), 20010 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 21600);

    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 1);

    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(21601, addr, 5 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr), 20015 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 21601);

    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 1);

    tracker.startPersistedTransaction();
    tracker.removeAddressTransaction(21601, addr, 5 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr), 20010 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 21600);

    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(21601, addr, -15 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr), 19995 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 21600);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getStart(), 21601);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getEnd(), 21601);

    // now since they spent more and broke the limit, they're not eligible anymore
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 0);

    // calling with a block that doesn't have a record should change nothing other than the balance
    tracker.startPersistedTransaction();
    tracker.removeAddressTransaction(22600, addr, 15 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr), 19980 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 21600);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getStart(), 21601);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getEnd(), 21601);

    // now since they spent more and broke the limit, they're not eligible anymore
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 0);
}

BOOST_AUTO_TEST_CASE(getEligibleAddresses)
{
    //test asserts
    BOOST_REQUIRE_THROW(tracker.getEligibleAddresses(1), std::invalid_argument);
    BOOST_REQUIRE_THROW(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan-1), std::invalid_argument);
    BOOST_REQUIRE_THROW(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan + 1), std::invalid_argument);
    BOOST_REQUIRE_THROW(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan + 5000), std::invalid_argument);

    // ok
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan).size(), 0);
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 2).size(), 0);
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 3).size(), 0);
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 50).size(), 0);

    std::string addrStr = "abc";
    AddressType addr = VecUint8FromString(addrStr);

    // 20001 coins added at block 1
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(1, addr, 20001 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // nobody is ever elegible in the first period.
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan).size(), 0);

    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 2).size(), 1);

    // address is always eligible in any of the next months.
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 2).size(), 1);
    BOOST_REQUIRE_EQUAL(StringFromVecUint8(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 2).front()), addrStr);
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 3).size(), 1);
    BOOST_REQUIRE_EQUAL(StringFromVecUint8(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 3).front()), addrStr);

    // until balance gets below 20k
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction((21600 * 3) + 1, addr, -2 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    // assert was eligable for month 3 in the past but not now
    BOOST_REQUIRE_THROW(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 3).size(), std::invalid_argument);
    BOOST_REQUIRE_THROW(StringFromVecUint8(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 3).front()), std::invalid_argument);

    // not eligable in month 4, this is ok.
    BOOST_REQUIRE_EQUAL(tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 4).size(), 0);
}

BOOST_AUTO_TEST_CASE(balance)
{
    std::string addrStr = "abc";
    AddressType addr = VecUint8FromString(addrStr);

    // add
    tracker.startPersistedTransaction();
    BOOST_REQUIRE_THROW(tracker.addAddressTransaction(1, addr, -1 * COIN, checkpoints), std::invalid_argument);
    tracker.endPersistedTransaction();

    // remove
    tracker.startPersistedTransaction();
    BOOST_REQUIRE_THROW(tracker.removeAddressTransaction(1, addr, 1 * COIN, checkpoints), std::invalid_argument);
    tracker.endPersistedTransaction();
}

BOOST_AUTO_TEST_CASE(interruption)
{
    std::string addrStr = "abc";
    AddressType addr = VecUint8FromString(addrStr);

    // 20001 coins added at block 1
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(1, addr, 20001 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr), 20001 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 1);

    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(1, addr, -2 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr), 19999 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getEnd(), 1);

    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(1, addr, 2 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr), 20001 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 3);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getEnd(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[2].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[2].getEnd(), 1);
    // ... possible DoS

    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(2, addr, -2 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 4);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getEnd(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[2].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[2].getEnd(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[3].getStart(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[3].getEnd(), 2);

    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(2, addr, 2 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 5);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getEnd(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[2].getStart(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[2].getEnd(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[3].getStart(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[3].getEnd(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[4].getStart(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[4].getEnd(), 2);
    // ...
}

std::string randomAddrGen(int length) {
    static std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    std::string result;
    result.resize(length);

    for (int i = 0; i < length; i++)
        result[i] = charset[rand() % charset.length()];

    return result;
}

BOOST_AUTO_TEST_CASE(performance)
{
    std::string addrStr = "abc";
    AddressType addr = VecUint8FromString(addrStr);

    // 20001 coins added at block 1
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(1, addr, 20001 * COIN, checkpoints);
    tracker.endPersistedTransaction();

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 2);
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();

    std::cout << "Elapsed: " << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count() << "[µs]" << std::endl;

    srand(time(NULL));

    for(int i = 0; i<5000; i++) {
        std::string addrStr = randomAddrGen(std::rand()%10);
        AddressType addr = VecUint8FromString(addrStr);

        // send some coin below 20k to all addresses
        tracker.startPersistedTransaction();
        tracker.addAddressTransaction(1, addr, rand()%20000 * COIN, checkpoints);
        tracker.endPersistedTransaction();
    }

    begin = std::chrono::steady_clock::now();
    tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 2);
    end = std::chrono::steady_clock::now();

    std::cout << "Elapsed: " << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count() << "[µs]" << std::endl;

    for(int i = 0; i<50000; i++) {
        std::string addrStr = randomAddrGen(std::rand()%10);
        AddressType addr = VecUint8FromString(addrStr);

        // send some coin below 20k to all addresses
        tracker.startPersistedTransaction();
        tracker.addAddressTransaction(1, addr, rand()%20000 * COIN, checkpoints);
        tracker.endPersistedTransaction();
    }

    begin = std::chrono::steady_clock::now();
    tracker.getEligibleAddresses(tracker.MinimumRewardRangeSpan * 2);
    end = std::chrono::steady_clock::now();

    std::cout << "Elapsed: " << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count() << "[µs]" << std::endl;
}

BOOST_AUTO_TEST_CASE(checkpoints_basic)
{
    // add a checkpoint at block 3
    checkpoints.insert(std::make_pair(3, uint256S("0x3333333333333333333333333333333333333333333333333333333333333333")));

    std::string addrStr = "abc";
    AddressType addr = VecUint8FromString(addrStr);

    BOOST_REQUIRE_THROW(balances.at(addr), std::out_of_range);

    // add something below last checkpoint is not allowed
    tracker.startPersistedTransaction();
    BOOST_REQUIRE_THROW(tracker.addAddressTransaction(1, addr, 20000 * COIN, checkpoints), std::invalid_argument);
    tracker.endPersistedTransaction();
    BOOST_CHECK_EQUAL(balances.at(addr), 0);
    BOOST_REQUIRE_EQUAL(ranges.size(), 0);

    // 20001 coins added at block 4 to insert a record
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(4, addr, 20000 * COIN, checkpoints);
    tracker.endPersistedTransaction();
    BOOST_CHECK_EQUAL(balances.at(addr), 20000 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 4);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 4);

    // change state to below 20k
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(5, addr, -1 * COIN, checkpoints);
    tracker.endPersistedTransaction();
    BOOST_CHECK_EQUAL(balances.at(addr), 19999 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 4);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 4);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getStart(), 5);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[1].getEnd(), 5);

    // add a new checkpoint in block 7, everything below should be deleted in the next operation
    checkpoints.insert(std::make_pair(7, uint256S("0x7777777777777777777777777777777777777777777777777777777777777777")));

    // add some transaction after the checkpoint, this will delete old records for address
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(8, addr, -1 * COIN, checkpoints);
    tracker.endPersistedTransaction();
    BOOST_CHECK_EQUAL(balances.at(addr), 19998 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 0);

    // make sure it it start working again
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(9, addr, 2 * COIN, checkpoints);
    tracker.endPersistedTransaction();
    BOOST_CHECK_EQUAL(balances.at(addr), 20000 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 9);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 9);
}

BOOST_AUTO_TEST_SUITE_END()
