#!/usr/bin/env python3
# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework, connect_nodes_bi
from test_framework.messages import COIN


class DevFundTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [['-debug', '-noacceptnonstdtxn', '-reservebalance=10000000', '-stakethreadconddelayms=500', '-txindex=1', '-maxtxfee=1'] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        self.sync_all()

    def run_test(self):
        nodes = self.nodes

        self.import_genesis_coins_a(nodes[0])
        self.import_genesis_coins_b(nodes[1])
        nodes[2].extkeyimportmaster(nodes[2].mnemonic('new')['master'])

        fund_addr = nodes[2].getnewaddress()
        for n in nodes:
            n.pushdevfundsetting({'timefrom': 0, 'fundaddress': fund_addr, 'minstakepercent': 10, 'outputperiod': 10})

        staking_opts = {
            'stakecombinethreshold': 50,
            'stakesplitthreshold': 100,
        }
        nodes[0].walletsettings('stakingoptions', staking_opts)
        nodes[0].walletsettings('stakelimit', {'height': 5})
        nodes[0].reservebalance(False)

        self.wait_for_height(nodes[0], 5)
        addr1 = nodes[1].getnewaddress()
        tx_hex = nodes[1].createrawtransaction(inputs=[], outputs={addr1: 1.0})
        tx_funded = nodes[1].fundrawtransaction(tx_hex, {'feeRate': 5.0})
        tx_fee = int(tx_funded['fee'] * COIN)
        tx_signed = nodes[1].signrawtransactionwithwallet(tx_funded['hex'])
        sent_txid = nodes[0].sendrawtransaction(tx_signed['hex'], 0)

        nodes[0].walletsettings('stakelimit', {'height': 6})
        self.wait_for_height(nodes[0], 6)

        sxaddr1 = nodes[1].getnewstealthaddress()
        txid = nodes[1].sendtypeto('part', 'blind', [{'address': sxaddr1, 'amount': 1.0}])
        nodes[0].sendrawtransaction(nodes[1].getrawtransaction(txid))
        rv = nodes[1].filtertransactions({'type': 'blind'})
        tx2_fee = int(float(rv[0]['fee']) * -1.0 * COIN)

        nodes[0].walletsettings('stakelimit', {'height': 12})
        self.wait_for_height(nodes[0], 12)

        base_supply = 125000 * COIN

        def get_coinstake_reward(moneysupply):
            target_spacing = 5  # 5 seconds
            coin_year_reward = int(2 * 1e6)  # 2%

            stakes_per_year = 365 * 24 * (60 * 60 // target_spacing)
            return (moneysupply // COIN) * coin_year_reward // stakes_per_year

        expect_reward = get_coinstake_reward(base_supply)
        assert(expect_reward == 39637)

        block_reward_5 = nodes[0].getblockreward(5)
        block_reward_6 = nodes[0].getblockreward(6)
        assert(block_reward_5['stakereward'] * COIN == expect_reward)
        assert(block_reward_5['blockreward'] * COIN == expect_reward - ((expect_reward * 10) // 100))
        assert(block_reward_6['stakereward'] * COIN == expect_reward)
        assert(block_reward_6['blockreward'] * COIN == expect_reward + tx_fee - (((expect_reward + tx_fee) * 10) // 100))

        # Foundation fund cut from high fees block is greater than the stake reward
        block5_header = nodes[0].getblockheader(nodes[0].getblockhash(5))
        block6_header = nodes[0].getblockheader(nodes[0].getblockhash(6))
        assert(block6_header['moneysupply'] < block5_header['moneysupply'])

        expect_foundation_payout = ((expect_reward * 10) // 100) * 8
        expect_foundation_payout += (((expect_reward + tx_fee) * 10) // 100)
        expect_foundation_payout += (((expect_reward + tx2_fee) * 10) // 100)
        assert(nodes[2].getbalances()['mine']['staked'] * COIN == expect_foundation_payout)

        expect_created = expect_reward * 12 - ((expect_reward * 10) // 100) * 2

        block12_header = nodes[0].getblockheader(nodes[0].getblockhash(12))
        assert(abs((block12_header['moneysupply'] * COIN - base_supply) - expect_created) < 10)


if __name__ == '__main__':
    DevFundTest().main()
