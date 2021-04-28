#!/usr/bin/env python3
# Copyright (c) 2019-2021 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework
import time

class MultiWalletTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [ ['-debug','-noacceptnonstdtxn','-reservebalance=10000000','-stakethreadconddelayms=100'] for i in range(self.num_nodes)]

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

        self.import_genesis_coins_a(nodes[0])
        self.import_genesis_coins_b(nodes[1])
        nodes[2].extkeyimportmaster('sección grito médula hecho pauta posada nueve ebrio bruto buceo baúl mitad')

        self.log.info('Check loaded wallets rescan any missed blocks')

        nodes[2].createwallet('wallet_2')
        assert(len(nodes[2].listwallets()) == 2)

        w1 = nodes[2].get_wallet_rpc('default_wallet')
        w2 = nodes[2].get_wallet_rpc('wallet_2')
        w2.extkeyimportmaster('sección grito médula hecho pauta posada nueve ebrio bruto buceo baúl mitad')

        addr = w1.getnewaddress()
        nodes[0].sendtoaddress(addr, 1000)
        self.stakeBlocks(1)
        assert(w1.getwalletinfo()['total_balance'] == 1000)
        assert(w2.getwalletinfo()['total_balance'] == 1000)

        nodes[2].unloadwallet('wallet_2')
        assert(len(nodes[2].listwallets()) == 1)

        nodes[2].sendtoaddress(nodes[1].getnewaddress(), 100)

        self.log.info('Test threshold values')
        nodes[2].createwallet('w4')
        nodes[2].createwallet('w5')
        nodes[2].createwallet('w6')
        w4 = nodes[2].get_wallet_rpc('w4')
        w5 = nodes[2].get_wallet_rpc('w5')
        w6 = nodes[2].get_wallet_rpc('w6')
        mnemonic = w4.mnemonic('new')['master']
        w4.extkeyimportmaster(mnemonic)
        w5.extkeyimportmaster(mnemonic)
        w6.extkeyimportmaster(mnemonic)
        w5.walletsettings('stakingoptions', {'minstakeablevalue' : 1.0})
        w6.walletsettings('other', {'minownedvalue' : 1.0})
        w4_addr = w4.getnewaddress()
        nodes[0].sendtoaddress(w4_addr, 1)
        nodes[0].sendtoaddress(w4_addr, 0.99)

        self.sync_all()
        self.stakeBlocks(1)

        nodes[2].loadwallet('wallet_2')
        w1 = nodes[2].get_wallet_rpc('default_wallet')
        w2 = nodes[2].get_wallet_rpc('wallet_2')

        assert(w1.getwalletinfo()['total_balance'] < 900)
        assert(w1.getwalletinfo()['total_balance'] == w2.getwalletinfo()['total_balance'])

        ro = nodes[2].getblockstats(nodes[2].getblockchaininfo()['blocks'])
        assert(ro['height'] == 2)

        self.log.info('createwallet with passphrase')

        nodes[2].createwallet('wallet_3', False, False, 'password_abc')
        w3 = nodes[2].get_wallet_rpc('wallet_3')
        ro = w3.getwalletinfo()
        assert('hdseedid' in ro)
        assert(ro['encryptionstatus'] == 'Locked')

        w4.reservebalance(False)
        w5.reservebalance(False)
        w6.reservebalance(False)
        time.sleep(0.5)
        assert(float(w4.getbalances()['mine']['trusted']) == 1.99)
        assert(float(w5.getbalances()['mine']['trusted']) == 1.99)
        assert(float(w6.getbalances()['mine']['trusted']) == 1.0)
        w4_stakinginfo = w4.getstakinginfo()
        w5_stakinginfo = w5.getstakinginfo()
        w6_stakinginfo = w6.getstakinginfo()
        assert(w4_stakinginfo['minstakeablevalue'] == 1)
        assert(w4_stakinginfo['weight'] == 199000000)
        assert(w5_stakinginfo['minstakeablevalue'] == 100000000)
        assert(w5_stakinginfo['weight'] == 100000000)
        assert(w6_stakinginfo['minstakeablevalue'] == 1)
        assert(w6_stakinginfo['weight'] == 100000000)
        assert(float(w6.walletsettings('other')['other']['minownedvalue']) == 1.0)


if __name__ == '__main__':
    MultiWalletTest().main()
