#!/usr/bin/env python3
# Copyright (c) 2018-2019 The Particl Core developers
# Copyright (c) 2020 The Ghost Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework
from test_framework.util import assert_raises_rpc_error



class WalletRPCBurnTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [ ['-debug'] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

        self.sync_all()

    def run_test(self):
        nodes = self.nodes

        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)

        #Burn 100 coins with op_return text as burntx
        nodes[0].burn(100,"burntx")
        #Check max char limit
        assert_raises_rpc_error(-8, "Comment cannot be longer than 80 characters", self.nodes[0].burn,1,"The clock within this blog and the clock on my laptop are 1 hour different from each other.")
        #Check burning works without any comment
        nodes[0].burn(1)

        self.sync_all()


if __name__ == '__main__':
    WalletRPCBurnTest().main()
