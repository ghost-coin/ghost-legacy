#!/usr/bin/env python3
# Copyright (c) 2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time

from test_framework.test_ghost import (
    GhostTestFramework,
    connect_nodes_bi,
    isclose
)

KEEP_FUNDING_TX_DATA = 86400 * 31

class SmsgRollingCacheTest(GhostTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True  # Don't copy from cache
        self.num_nodes = 3
        self.extra_args = [ ['-debug', '-reservebalance=10000000'] for i in range(self.num_nodes) ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)

    def run_test(self):
        nodes = self.nodes

        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)

        nodes[1].extkeyimportmaster('pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true')
        nodes[1].getnewextaddress('lblExtTest')
        nodes[1].rescanblockchain()
        assert(nodes[1].getwalletinfo()['total_balance'] == 25000)

        nodes[2].extkeyimportmaster(nodes[2].mnemonic('new')['master'])

        address1 = nodes[1].getnewaddress()
        nodes[1].smsgaddlocaladdress(address1)
        nodes[2].smsgaddaddress(address1, nodes[1].smsglocalkeys()['wallet_keys'][0]['public_key'])

        address0 = nodes[0].getnewaddress()
        address1 = nodes[1].getnewaddress()
        nodes[0].smsgaddlocaladdress(address0)
        nodes[1].smsgaddaddress(address0, nodes[0].smsglocalkeys()['wallet_keys'][0]['public_key'])

        text = 'Some text to test'
        ro = nodes[1].smsgsend(address1, address0, text, True, 10)
        assert(ro['result'] == 'Sent.')
        assert(isclose(ro['fee'], 0.00159000))

        self.stakeBlocks(1, nStakeNode=1)

        self.log.info('Waiting for paid smsg to send')
        for i in range(20):
            txns = nodes[1].smsgdebug('dumpfundingtxids')
            if len(txns['txns']) < 1:
                time.sleep(1)
                continue
            break
        assert(len(txns['txns']) > 0)

        now = int(time.time())
        for i in range(len(nodes)):
           nodes[i].setmocktime(now + KEEP_FUNDING_TX_DATA, True)

        self.log.info('Waiting for rolling cache to expire')
        for i in range(60):
            txns = nodes[1].smsgdebug('dumpfundingtxids')
            if len(txns['txns']) > 0:
                time.sleep(1)
                continue
            break
        assert(len(txns['txns']) == 0)

        self.log.info('Done.')


if __name__ == '__main__':
    SmsgRollingCacheTest().main()
