#!/usr/bin/env python3
# Copyright (c) 2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework, connect_nodes_bi


class TraceFrozenOutputsTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [['-debug', '-noacceptnonstdtxn', '-reservebalance=10000000', '-stakethreadconddelayms=500', '-txindex=1'] for i in range(self.num_nodes)]

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

        nodes[1].createwallet('w1')
        nodes[1].createwallet('w2')
        w1_0 = nodes[1].get_wallet_rpc('')
        w1_1 = nodes[1].get_wallet_rpc('w1')
        w1_1.extkeyimportmaster(w1_1.mnemonic('new')['master'])
        w1_2 = nodes[1].get_wallet_rpc('w2')
        w1_2.extkeyimportmaster(w1_2.mnemonic('new')['master'])

        w1_0_addr = w1_0.getnewstealthaddress()
        w1_1_addr = w1_1.getnewstealthaddress()
        w1_2_addr = w1_2.getnewstealthaddress()

        txid_p2b = w1_0.sendtypeto('part', 'blind', [{'address': w1_1_addr, 'amount': 200}])
        nodes[0].sendrawtransaction(nodes[1].getrawtransaction(txid_p2b))
        self.stakeBlocks(1)

        for i in range(20):
            txid_b2a = w1_1.sendtypeto('blind', 'anon', [{'address': w1_2_addr, 'amount': 9}])
            nodes[0].sendrawtransaction(nodes[1].getrawtransaction(txid_b2a))
        self.stakeBlocks(2)

        txid_a2a = w1_2.sendtypeto('anon', 'anon', [{'address': w1_0_addr, 'amount': 20}])
        nodes[0].sendrawtransaction(nodes[1].getrawtransaction(txid_a2a))
        self.stakeBlocks(2)

        n = w1_0.filtertransactions()[0]['outputs'][0]['vout']
        traced = w1_0.debugwallet({'trace_frozen_outputs': True, 'trace_frozen_extra': [{'tx': txid_a2a, 'n': n}]})

        found_at_depth = -1

        def check_tx(tx, depth):
            if tx['input_type'] == 'plain':
                return depth
            if 'inputs' in tx:
                for txi in tx['inputs']:
                    return check_tx(txi, depth + 1)
            return -1

        for tx in traced['transactions']:
            found_at_depth = check_tx(tx, 0)

        assert(found_at_depth >= 1)


if __name__ == '__main__':
    TraceFrozenOutputsTest().main()
