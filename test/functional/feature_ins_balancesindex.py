#!/usr/bin/env python3
# Copyright (c) 2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework


class BalancesIndexTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            ['-debug', ],
            ['-debug', '-balancesindex'],
            ['-debug', '-balancesindex'], ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

        self.connect_nodes_bi(0, 1)
        self.connect_nodes_bi(0, 2)

        self.sync_all()

    def run_test(self):
        nodes = self.nodes

        for i in range(len(nodes)):
            nodes[i].reservebalance(True, 10000000)  # Stop staking

        self.import_genesis_coins_a(nodes[0])
        self.import_genesis_coins_b(nodes[1])

        nodes[2].extkeyimportmaster(nodes[2].mnemonic('new')['master'])

        r = nodes[1].getinsightinfo()
        assert(r['balancesindex'] is True)

        r = nodes[1].getblockbalances(nodes[0].getblockhash(0))
        assert(r['plain'] == 125000.0)

        sx_addr_2 = nodes[2].getnewstealthaddress()
        nodes[0].sendtypeto('part', 'anon', [{'address': sx_addr_2, 'amount': 10.0}])
        nodes[0].sendtypeto('part', 'blind', [{'address': sx_addr_2, 'amount': 11.0}])

        self.stakeBlocks(1)

        r = nodes[1].getblockbalances(nodes[0].getblockhash(1), {'in_sats': True})
        assert(r['plain'] == 12497900039637)
        assert(r['blind'] == 1100000000)
        assert(r['anon'] == 1000000000)

        txid = nodes[2].sendtypeto('blind', 'part', [{'address': sx_addr_2, 'amount': 2.0, 'subfee': True}])
        tx_raw = nodes[2].getrawtransaction(txid)
        nodes[0].sendrawtransaction(tx_raw)

        self.stakeBlocks(1)

        blockbalances = nodes[1].getblockbalances(nodes[0].getblockhash(2))
        assert(blockbalances['blind'] == 9.0)

        txoutsetinfo = nodes[1].gettxoutsetinfo()
        assert(blockbalances['plain'] == txoutsetinfo['total_amount'])


if __name__ == '__main__':
    BalancesIndexTest().main()
