#!/usr/bin/env python3
# Copyright (C) 2017-2019 The Particl Core developers
# Copyright (C) 2020 The Ghost Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time

from test_framework.test_ghost import GhostTestFramework, connect_nodes_bi
from test_framework.authproxy import JSONRPCException


class ForkTest(GhostTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 6
        self.extra_args = [ ['-debug',] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 1, 2)

        connect_nodes_bi(self.nodes, 3, 4)
        connect_nodes_bi(self.nodes, 3, 5)
        connect_nodes_bi(self.nodes, 4, 5)

        self.sync_all()

    def run_test(self):
        nodes = self.nodes

        # stop staking
        nodes[0].reservebalance(True, 10000000)
        nodes[3].reservebalance(True, 10000000)

        nodes[0].extkeyimportmaster('pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true')
        nodes[0].getnewextaddress('lblExtTest')
        nodes[0].rescanblockchain()
        assert(nodes[0].getwalletinfo()['total_balance'] == 25000)

        nodes[3].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[3].getwalletinfo()['total_balance'] == 100000)

        n0_wi_before = nodes[0].getwalletinfo()

        # start staking
        nBlocksShorterChain = 2
        nBlocksLongerChain = 5

        ro = nodes[0].walletsettings('stakelimit', {'height':nBlocksShorterChain})
        ro = nodes[3].walletsettings('stakelimit', {'height':nBlocksLongerChain})
        ro = nodes[0].reservebalance(False)
        ro = nodes[3].reservebalance(False)


        self.wait_for_height(nodes[0], nBlocksShorterChain, 1000)

        # stop group1 from staking
        ro = nodes[0].reservebalance(True, 10000000)


        self.wait_for_height(nodes[3], nBlocksLongerChain, 2000)

        # stop group2 from staking
        ro = nodes[3].reservebalance(True, 10000000)

        node0_chain = []
        for k in range(1, nBlocksLongerChain+1):
            try:
                ro = nodes[0].getblockhash(k)
            except JSONRPCException as e:
                assert('Block height out of range' in e.error['message'])
                ro = ''
            node0_chain.append(ro)
            print('node0 ',k, " - ", ro)

        node3_chain = []
        for k in range(1, 6):
            ro = nodes[3].getblockhash(k)
            node3_chain.append(ro)
            print('node3 ',k, ' - ', ro)


        # connect groups
        connect_nodes_bi(self.nodes, 0, 3)

        fPass = False
        for i in range(15):
            time.sleep(2)

            fPass = True
            for k in range(1, nBlocksLongerChain+1):
                try:
                    ro = nodes[0].getblockhash(k)
                except JSONRPCException as e:
                    assert('Block height out of range' in e.error['message'])
                    ro = ''
                if not ro == node3_chain[k]:
                    fPass = False
                    break
            if fPass:
                break
        #assert(fPass)


        node0_chain = []
        for k in range(1, nBlocksLongerChain+1):
            try:
                ro = nodes[0].getblockhash(k)
            except JSONRPCException as e:
                assert('Block height out of range' in e.error['message'])
                ro = ''
            node0_chain.append(ro)
            print('node0 ',k, ' - ', ro)


        ro = nodes[0].getblockchaininfo()
        assert(ro['blocks'] == 5)
        ro = nodes[3].getblockchaininfo()
        assert(ro['blocks'] == 5)

        n0_wi_after = nodes[0].getwalletinfo()

        assert(n0_wi_after['total_balance'] == n0_wi_before['total_balance'])
        assert(n0_wi_before['txcount'] == 1)
        assert(n0_wi_after['txcount'] == 3)

        n0_ft = nodes[0].filtertransactions()
        assert(len(n0_ft) == 3)
        assert(n0_ft[0]['category'] == 'orphaned_stake')
        assert(n0_ft[1]['category'] == 'orphaned_stake')
        n0_lt = nodes[0].listtransactions()
        assert(n0_lt[-1]['category'] == 'orphaned_stake')
        assert(n0_lt[-2]['category'] == 'orphaned_stake')


if __name__ == '__main__':
    ForkTest().main()
