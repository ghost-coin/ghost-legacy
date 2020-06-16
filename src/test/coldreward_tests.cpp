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
    }

    ~ColdRewardsSetup()
    {
    }

    ColdRewardTracker tracker;
    using AddressType = ColdRewardTracker::AddressType;

    // we use these to simulate database storage
    std::map<AddressType, CAmount> balances;
    std::map<AddressType, std::vector<BlockHeightRange>> ranges;
};

namespace {
ColdRewardTracker::AddressType VecUint8FromString(const std::string& str)
{
    return ColdRewardTracker::AddressType(str.cbegin(), str.cend());
}
} // namespace


BOOST_FIXTURE_TEST_SUITE(coldreward_tests, ColdRewardsSetup)

BOOST_AUTO_TEST_CASE(basics)
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

    std::string addrStr = "abc";
    AddressType addr = VecUint8FromString(addrStr);

    // 10 coins added at block 50
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(50, addr, 10 * COIN);
    tracker.endPersistedTransaction();

    // balance changes with no range changes, because nothing exceeded 20k
    BOOST_CHECK_EQUAL(balances.at(addr), 10 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 0);

    // add 20k coins at block 51
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(51, addr, 20000 * COIN);
    tracker.endPersistedTransaction();

    // now we have one new range entry + balance update
    BOOST_CHECK_EQUAL(balances.at(addr), 20010 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 51);

    // subtract 5 coins at block 52
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(52, addr, -5 * COIN);
    tracker.endPersistedTransaction();

    // now that range entry got extended becasue we're still over 20k
    BOOST_CHECK_EQUAL(balances.at(addr), 20005 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 52);

    // subtract 5 coins at block 100
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(100, addr, -5 * COIN);
    tracker.endPersistedTransaction();

    // we're still equal or over 20k, so the range is extended
    BOOST_CHECK_EQUAL(balances.at(addr), 20000 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getStart(), 51);
    BOOST_REQUIRE_EQUAL(ranges.at(addr)[0].getEnd(), 100);

    // subtract 5 coins at block 110
    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(110, addr, -5 * COIN);
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
    tracker.removeAddressTransaction(110, addr, -5 * COIN);
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
    tracker.addAddressTransaction(101, addr, -5 * COIN);
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
    tracker.removeAddressTransaction(101, addr, -5 * COIN);
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
    tracker.removeAddressTransaction(100, addr, 0 * COIN);
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
    tracker.addAddressTransaction(101, addr, -5 * COIN);
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

    //////////////////////

    // some corner cases
    std::string addr2Str = "abc2";
    AddressType addr2 = VecUint8FromString(addr2Str);

    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(10, addr2, 20000 * COIN);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr2), 20000 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getEnd(), 10);

    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);

    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(21599, addr2, 5 * COIN);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr2), 20005 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getEnd(), 21599);

    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 1);

    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(21600, addr2, 5 * COIN);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr2), 20010 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getEnd(), 21600);

    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(21600).size(), 0);
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 1);

    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(21601, addr2, 5 * COIN);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr2), 20015 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getEnd(), 21601);

    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 1);

    tracker.startPersistedTransaction();
    tracker.removeAddressTransaction(21601, addr2, 5 * COIN);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr2), 20010 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2).size(), 1);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getEnd(), 21600);

    tracker.startPersistedTransaction();
    tracker.addAddressTransaction(21601, addr2, -15 * COIN);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr2), 19995 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2).size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getEnd(), 21600);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[1].getStart(), 21601);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[1].getEnd(), 21601);

    // now since they spent more and broke the limit, they're not eligible anymore
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 0);

    // calling with a block that doesn't have a record should change nothing other than the balance
    tracker.startPersistedTransaction();
    tracker.removeAddressTransaction(22600, addr2, 15 * COIN);
    tracker.endPersistedTransaction();

    BOOST_CHECK_EQUAL(balances.at(addr2), 19980 * COIN);
    BOOST_REQUIRE_EQUAL(ranges.size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2).size(), 2);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getStart(), 10);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[0].getEnd(), 21600);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[1].getStart(), 21601);
    BOOST_REQUIRE_EQUAL(ranges.at(addr2)[1].getEnd(), 21601);

    // now since they spent more and broke the limit, they're not eligible anymore
    BOOST_CHECK_EQUAL(tracker.getEligibleAddresses(2 * 21600).size(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
