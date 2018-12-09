#!/usr/bin/env python3
# Copyright (c) 2017-2018 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import ParticlTestFramework
from test_framework.test_particl import isclose, getIndexAtProperty
from test_framework.util import *
import binascii


class SmsgPaidFeeTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [ ['-debug','-noacceptnonstdtxn','-reservebalance=10000000'] for i in range(self.num_nodes) ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()
        connect_nodes(self.nodes[0], 1)

        self.sync_all()

    def run_test (self):
        tmpdir = self.options.tmpdir
        nodes = self.nodes

        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)

        nodes[1].extkeyimportmaster('pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true')
        nodes[1].getnewextaddress('lblExtTest')
        nodes[1].rescanblockchain()
        assert(nodes[1].getwalletinfo()['total_balance'] == 25000)

        assert(nodes[0].smsggetfeerate() == 50000)

        self.stakeBlocks(1)

        ro = nodes[0].getblock(nodes[0].getblockhash(1), 2)
        assert(float(ro['tx'][0]['vout'][0]['smsgfeerate']) == 0.0005)

        ro = nodes[0].walletsettings('stakingoptions', {'smsgfeeratetarget' : 0.001})
        assert(float(ro['stakingoptions']['smsgfeeratetarget']) == 0.001)

        self.stakeBlocks(1)

        ro = nodes[0].getblock(nodes[0].getblockhash(2), 2)
        assert(float(ro['tx'][0]['vout'][0]['smsgfeerate']) == 0.00050215)
        blk2_hex = nodes[0].getblock(nodes[0].getblockhash(2), 0)

        nodes[0].rewindchain(1)
        nodes[1].rewindchain(1)

        assert(nodes[0].getblockchaininfo()['blocks'] == 1)

        blockBytes = bytearray.fromhex(blk2_hex)
        assert(blockBytes[112] == 1)  # nTx
        assert(blockBytes[113] == 0xa0)  # tx version
        assert(blockBytes[114] == 0x02)  # tx type (coinstake)

        assert(blockBytes[119] == 0x01)  # nInputs

        assert(blockBytes[156] == 0x00)  # scriptSig

        assert(blockBytes[161] == 0x03)  # num outputs
        assert(blockBytes[162] == 0x04)  # OUTPUT_DATA



if __name__ == '__main__':
    SmsgPaidFeeTest().main()
