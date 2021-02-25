#!/usr/bin/env python3
# Copyright (c) 2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time

from test_framework.test_particl import ParticlTestFramework
from test_framework.messages import COIN


class DisableTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [['-hf1time=0', '-debug', '-acceptanontxn', '-acceptblindtxn', '-noacceptnonstdtxn', '-reservebalance=10000000', '-stakethreadconddelayms=500', '-txindex=1', '-maxtxfee=1', ] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

        self.connect_nodes_bi(0, 1)
        self.connect_nodes_bi(0, 2)
        self.sync_all()

    def run_test(self):
        nodes = self.nodes

        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)

        nodes[1].extkeyimportmaster('pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true')
        nodes[1].getnewextaddress('lblExtTest')
        nodes[1].rescanblockchain()
        assert(nodes[1].getwalletinfo()['total_balance'] == 25000)

        #for node in nodes:
            #node.setmocktime(1614168000)  # 2021-02-24 12:00

        sx0 = nodes[0].getnewstealthaddress()
        sx1 = nodes[1].getnewstealthaddress()

        txids = []
        txids.append(nodes[1].sendtypeto('part', 'part', [{'address': sx0, 'amount': 10},]))
        txids.append(nodes[1].sendtypeto('part', 'blind', [{'address': sx0, 'amount': 12},]))
        txids.append(nodes[1].sendtypeto('part', 'blind', [{'address': sx1, 'amount': 13},]))
        txids.append(nodes[1].sendtypeto('part', 'anon', [{'address': sx0, 'amount': 14},]))
        txids.append(nodes[1].sendtypeto('part', 'anon', [{'address': sx0, 'amount': 15},]))
        for i in range(20):
            txids.append(nodes[1].sendtypeto('part', 'anon', [{'address': sx1, 'amount': 1},]))

        for h in txids:
            assert(self.wait_for_mempool(nodes[0], h))

        self.stakeBlocks(2)

        txids = []
        txids.append(nodes[1].sendtypeto('anon', 'part', [{'address': sx1, 'amount': 1},]))
        txids.append(nodes[1].sendtypeto('anon', 'blind', [{'address': sx1, 'amount': 1},]))
        txids.append(nodes[1].sendtypeto('anon', 'anon', [{'address': sx1, 'amount': 1},]))
        txids.append(nodes[1].sendtypeto('blind', 'part', [{'address': sx1, 'amount': 1},]))
        txids.append(nodes[1].sendtypeto('blind', 'anon', [{'address': sx1, 'amount': 1},]))

        for h in txids:
            assert(self.wait_for_mempool(nodes[1], h))

        self.stakeBlocks(1)

        self.stop_node(1)
        self.start_node(1, ['-wallet=default_wallet', '-noacceptanontxn', '-noacceptblindtxn', '-hf1time=0', '-checklevel=1', '-noacceptnonstdtxn', '-reservebalance=10000000', '-debug'])
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)

        txids = []
        txids.append(nodes[1].sendtypeto('part', 'part', [{'address': sx0, 'amount': 1},]))
        assert(self.wait_for_mempool(nodes[1], txids[-1]))

        try:
            nodes[1].sendtypeto('part', 'blind', [{'address': sx1, 'amount': 1},])
            assert(False)
        except Exception:
            pass
        try:
            nodes[1].sendtypeto('blind', 'part', [{'address': sx1, 'amount': 1},])
            assert(False)
        except Exception:
            pass
        try:
            nodes[1].sendtypeto('blind', 'anon', [{'address': sx1, 'amount': 1},])
            assert(False)
        except Exception:
            pass
        try:
            nodes[1].sendtypeto('anon', 'part', [{'address': sx1, 'amount': 1},])
            assert(False)
        except Exception:
            pass
        try:
            nodes[1].sendtypeto('anon', 'anon', [{'address': sx1, 'amount': 1},])
            assert(False)
        except Exception:
            pass
        try:
            nodes[1].sendtypeto('part', 'anon', [{'address': sx1, 'amount': 1},])
            assert(False)
        except Exception:
            pass

        txids = []
        txids.append(nodes[0].sendtypeto('anon', 'anon', [{'address': sx1, 'amount': 1},]))
        txids.append(nodes[0].sendtypeto('part', 'anon', [{'address': sx1, 'amount': 1},]))
        txids.append(nodes[0].sendtypeto('anon', 'part', [{'address': sx1, 'amount': 1},]))
        txids.append(nodes[0].sendtypeto('part', 'blind', [{'address': sx1, 'amount': 1},]))
        txids.append(nodes[0].sendtypeto('blind', 'part', [{'address': sx1, 'amount': 1},]))
        txids.append(nodes[0].sendtypeto('blind', 'anon', [{'address': sx1, 'amount': 1},]))
        txids.append(nodes[0].sendtypeto('anon', 'blind', [{'address': sx1, 'amount': 1},]))

        for txid in txids:
            rtx = nodes[0].getrawtransaction(txid)
            try:
                nodes[1].sendrawtransaction(rtx)
                assert(False)
            except Exception as e:
                assert('bad-txns-anon-disabled' in str(e) or 'bad-txns-blind-disabled' in str(e))


if __name__ == '__main__':
    DisableTest().main()
