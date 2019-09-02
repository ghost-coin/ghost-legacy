#!/usr/bin/env python3
# Copyright (c) 2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time

from test_framework.test_particl import ParticlTestFramework
from test_framework.util import connect_nodes_bi


class SmsgMultiWalletTest(ParticlTestFramework):
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

        nodes[2].createwallet('wallet_2')
        w1 = nodes[2].get_wallet_rpc('')
        w2 = nodes[2].get_wallet_rpc('wallet_2')
        w2.extkeyimportmaster(nodes[2].mnemonic('new')['master'])
        w2.encryptwallet('qwerty234')

        smsg_info = nodes[2].smsggetinfo()
        assert(len(smsg_info['enabled_wallets']) == 2)

        address2_1 = w1.getnewaddress()
        address2_1_info = w1.getaddressinfo(address2_1)
        address2_2 = w2.getnewaddress()
        address2_2_info = w2.getaddressinfo(address2_2)
        nodes[2].smsgaddlocaladdress(address2_1)
        nodes[2].smsgaddlocaladdress(address2_2)

        addr2_1_sx = w1.getnewstealthaddress()
        dest2_3 = w1.derivefromstealthaddress(addr2_1_sx)
        dest2_3 = w1.derivefromstealthaddress(addr2_1_sx, dest2_3['ephemeral_pubkey'])
        pubkey2_3 = dest2_3['pubkey']
        privkey2_3 = dest2_3['privatekey']
        address2_3 = dest2_3['address']
        nodes[2].smsgimportprivkey(privkey2_3, 'smsg test address2_3')

        nodes[1].smsgaddaddress(address2_1, address2_1_info['pubkey'])
        nodes[1].smsgaddaddress(address2_2, address2_2_info['pubkey'])
        nodes[1].smsgaddaddress(address2_3, pubkey2_3)

        nodes[1].smsgsend(address1, address2_1, 'test 1')
        nodes[1].smsgsend(address1, address2_2, 'test 2')
        nodes[1].smsgsend(address1, address2_3, 'test 3')

        i = 0
        for i in range(20):
            ro = nodes[2].smsginbox()
            if len(ro['messages']) > 1:
                break
            time.sleep(1)
        assert(i < 19)

        assert(len(ro['messages']) == 2)

        w2.walletpassphrase('qwerty234', 30)

        i = 0
        for i in range(20):
            ro = nodes[2].smsginbox()
            if len(ro['messages']) > 0:
                break
            time.sleep(1)
        assert(i < 19)

        assert(len(ro['messages']) == 1)


if __name__ == '__main__':
    SmsgMultiWalletTest().main()
