#!/usr/bin/env python3
# Copyright (c) 2021 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework, connect_nodes_bi


class VoteTestExtra(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [ ['-debug','-noacceptnonstdtxn','-reservebalance=10000000'] for i in range(self.num_nodes)]

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

        ro = nodes[0].setvote(1, 1, 0, 3)
        assert(ro['result'] == 'Voting for option 1 on proposal 1')
        ro = nodes[0].setvote(1, 2, 0, 3)
        assert(ro['result'] == 'Voting for option 2 on proposal 1')
        ro = nodes[0].setvote(1, 3, 4, 8)
        assert(ro['result'] == 'Voting for option 3 on proposal 1')
        ro = nodes[0].setvote(1, 4, 6, 9)
        assert(ro['result'] == 'Voting for option 4 on proposal 1')

        ro = nodes[0].votehistory(True, True)

        assert(ro[0]['proposal'] == 1)
        assert(ro[0]['option'] == 2)
        assert(ro[0]['from_height'] == 0)
        assert(ro[0]['to_height'] == 3)

        assert(ro[1]['proposal'] == 1)
        assert(ro[1]['option'] == 3)
        assert(ro[1]['from_height'] == 4)
        assert(ro[1]['to_height'] == 6)

        assert(ro[2]['proposal'] == 1)
        assert(ro[2]['option'] == 4)
        assert(ro[2]['from_height'] == 6)
        assert(ro[2]['to_height'] == 9)

        self.stakeBlocks(10)

        for i in range(1, 11):
            block_hash = nodes[0].getblockhash(i)
            ro = nodes[0].getblock(block_hash, 3)

            if i  < 4:
                assert(ro['tx'][0]['vout'][0]['vote'] == '1, 2')
            elif i  < 6:
                assert(ro['tx'][0]['vout'][0]['vote'] == '1, 3')
            elif i  < 10:
                assert(ro['tx'][0]['vout'][0]['vote'] == '1, 4')
            else:
                assert('vote' not in ro['tx'][0]['vout'][0])

if __name__ == '__main__':
    VoteTestExtra().main()
