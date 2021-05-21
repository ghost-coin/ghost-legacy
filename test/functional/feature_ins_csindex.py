#!/usr/bin/env python3
# Copyright (c) 2019-2021 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import re
import json

from test_framework.test_particl import ParticlTestFramework
from test_framework.authproxy import JSONRPCException


class TxIndexTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            ['-debug', ],
            ['-debug', '-txindex', '-csindex'],
            ['-debug', '-txindex', '-csindex'], ]

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
        assert(r['txindex'] is True)
        assert(r['coldstakeindex'] is True)

        addrStake = nodes[2].getnewaddress('addrStake')
        addrSpend = nodes[2].getnewaddress('addrSpend', 'false', 'false', 'true')

        addrStake2 = nodes[2].getnewaddress('addrStake2')
        addrSpend2 = nodes[2].getnewaddress('addrSpend2', 'false', 'false', 'true')

        #for i in range(len(nodes)):
        #   nodes[i].setmocktime(1530566486, True)  # Clamp for more consistent runtime

        self.stakeBlocks(1)

        toScript = nodes[1].buildscript({'recipe': 'ifcoinstake', 'addrstake': addrStake, 'addrspend': addrSpend})
        nodes[1].sendtypeto('part', 'part',
                            [{'address': 'script', 'amount': 12000, 'script': toScript['hex']},
                             {'address': 'script', 'amount': 12000, 'script': toScript['hex']}])

        addrStake2_stakeonly = nodes[1].validateaddress(addrStake2, True)['stakeonly_address']
        toScript = nodes[1].buildscript({'recipe': 'ifcoinstake', 'addrstake': addrStake2_stakeonly, 'addrspend': addrSpend2})
        nodes[1].sendtypeto('part', 'part',
                            [{'address': 'script', 'amount': 12, 'script': toScript['hex']}])

        try:
            nodes[1].sendtoaddress(addrStake2_stakeonly, 12)
            assert(False), 'Sent to stakeonly address'
        except JSONRPCException as e:
            assert('Can\'t send to stake-only address version' in e.error['message'])

        try:
            nodes[1].sendtypeto('part', 'part',
                                [{'address': addrStake2_stakeonly, 'amount':12}])
            assert(False), 'Sent to stakeonly address'
        except JSONRPCException as e:
            assert('Can\'t send to stake-only address version' in e.error['message'])

        self.sync_all()

        ro = nodes[2].listcoldstakeunspent(addrStake)
        assert(len(ro) == 0)

        try:
            ro = nodes[0].listcoldstakeunspent(addrStake)
            assert(False), 'listcoldstakeunspent without -csindex.'
        except JSONRPCException as e:
            assert(re.search('Requires -(?:cs|tx)index enabled', e.error['message']))

        self.stakeBlocks(1)
        ro = nodes[2].listcoldstakeunspent(addrStake)
        assert(len(ro) == 2)
        assert(ro[0]['value'] == ro[1]['value'] == 1200000000000)
        assert(ro[0]['addrspend'] == ro[1]['addrspend'] == addrSpend)
        ro = nodes[2].listcoldstakeunspent(addrStake, 2, {'mature_only': True})
        assert(len(ro) == 0)
        ro = nodes[2].listcoldstakeunspent(addrStake, 2, {'mature_only': True, 'all_staked': True})
        assert(len(ro) == 0)

        ro = nodes[2].listcoldstakeunspent(addrStake2)
        assert(len(ro) == 1)
        assert(ro[0]['value'] == 1200000000)
        assert(ro[0]['addrspend'] == addrSpend2)

        ro2 = nodes[2].listcoldstakeunspent(addrStake2_stakeonly)
        assert(json.dumps(ro2) == json.dumps(ro))

        self.stakeBlocks(1)

        # Lock the addrStake2 unspent, the unspents on addrStake must stake in the next block
        ro = nodes[2].listcoldstakeunspent(addrStake2_stakeonly, -1, {'show_outpoints': True})
        assert(nodes[2].lockunspent(False, [{'txid': ro[0]['txid'], 'vout': ro[0]['n']}]) == True)

        self.stakeBlocks(1, nStakeNode=2)
        ro = nodes[2].listcoldstakeunspent(addrStake)
        assert(len(ro) == 3)

        ro = nodes[2].listcoldstakeunspent(addrStake, 4, {'mature_only': True})
        assert(len(ro) == 1)
        ro = nodes[2].listcoldstakeunspent(addrStake, 4, {'mature_only': True, 'all_staked': True})
        assert(len(ro) == 3)

        ro = nodes[2].rewindchain()
        assert(ro['to_height'] == 3)
        ro = nodes[2].getblockchaininfo()
        assert(ro['blocks'] == 3)

        ro = nodes[2].listcoldstakeunspent(addrStake, 4)
        assert(ro[0]['height'] == 2)
        assert(ro[1]['height'] == 2)
        assert(len(ro) == 2)

        ro = nodes[1].listcoldstakeunspent(addrStake)
        assert(len(ro) == 3)

        self.restart_node(1, extra_args=self.extra_args[1] + ['-wallet=default_wallet',])

        ro = nodes[1].listcoldstakeunspent(addrStake)
        assert(len(ro) == 3)

        ro = nodes[1].getblockreward(2)
        assert(ro['stakereward'] < ro['blockreward'])

        self.restart_node(0, extra_args=self.extra_args[0] + ['-wallet=default_wallet',])
        self.restart_node(2, extra_args=self.extra_args[2] + ['-wallet=default_wallet',])
        self.connect_nodes_bi(0, 1)
        self.connect_nodes_bi(0, 2)

        ms_addrs0 = []
        ms_pubkeys0 = []
        ms_addrs1 = []
        ms_pubkeys1 = []

        ms_addrs0.append(nodes[0].getnewaddress())
        ms_addrs0.append(nodes[1].getnewaddress())
        ms_pubkeys0.append(nodes[0].getaddressinfo(ms_addrs0[0])['pubkey'])
        ms_pubkeys0.append(nodes[1].getaddressinfo(ms_addrs0[1])['pubkey'])

        ms_addr0 = nodes[0].addmultisigaddress_part(1, ms_pubkeys0)

        ms_addrs1.append(nodes[0].getnewaddress())
        ms_addrs1.append(nodes[1].getnewaddress())
        ms_pubkeys1.append(nodes[0].getaddressinfo(ms_addrs1[0])['pubkey'])
        ms_pubkeys1.append(nodes[1].getaddressinfo(ms_addrs1[1])['pubkey'])

        ms_addr1 = nodes[0].addmultisigaddress_part(1, ms_pubkeys1, '', False, True)

        script_ms_addr0 = nodes[1].buildscript({'recipe': 'ifcoinstake', 'addrstake': addrStake, 'addrspend': ms_addr0['address']})
        script_ms_addr1 = nodes[1].buildscript({'recipe': 'ifcoinstake', 'addrstake': addrStake, 'addrspend': ms_addr1['address']})


        txid = nodes[1].sendtypeto(
            'part', 'part',
            [{'address': 'script', 'amount': 1, 'script': script_ms_addr0['hex']},
             {'address': 'script', 'amount': 2, 'script': script_ms_addr1['hex']}])

        nodes[0].sendrawtransaction(nodes[1].getrawtransaction(txid))  # Quicker than syncing mempool

        self.stakeBlocks(1)
        ro = nodes[2].listcoldstakeunspent(addrStake)

        num_found = 0
        for o in ro:
            if o['addrspend'] in (ms_addr0['address'], ms_addr1['address']):
                num_found += 1
        assert(num_found == 2)


if __name__ == '__main__':
    TxIndexTest().main()
