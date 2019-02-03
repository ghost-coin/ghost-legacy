#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_particl import (
    ParticlTestFramework,
    isclose,
)
from test_framework.util import connect_nodes


class SmsgPaidFeeExtTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-debug', '-nocheckblockindex', '-noacceptnonstdtxn', '-reservebalance=10000000'] for i in range(self.num_nodes)]

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

        address0 = nodes[0].getnewaddress()
        address1 = nodes[1].getnewaddress()
        nodes[0].smsgaddlocaladdress(address0)
        nodes[1].smsgaddaddress(address0, nodes[0].smsglocalkeys()['wallet_keys'][0]['public_key'])

        text = 'Some text to test'
        ro = nodes[1].smsgsend(address1, address0, text, True, 10, True)
        print(ro)
        assert(ro['result'] == 'Not Sent.')
        assert(isclose(ro['fee'], 0.00157000))


        assert(nodes[0].smsggetfeerate() == 50000)
        assert(nodes[1].smsggetfeerate() == 50000)

        ro = nodes[0].walletsettings('stakingoptions', {'smsgfeeratetarget' : 0.001})
        assert(float(ro['stakingoptions']['smsgfeeratetarget']) == 0.001)

        self.stakeBlocks(49)
        assert(nodes[0].smsggetfeerate() == 50000)

        ro = nodes[1].smsgsend(address1, address0, text, True, 10)
        assert(ro['result'] == 'Sent.')
        assert('msgid' in ro)
        assert('txid' in ro)
        assert(isclose(ro['fee'], 0.00157000))

        self.stakeBlocks(1)
        assert(nodes[0].smsggetfeerate() == 61939)

        ro = nodes[1].smsgsend(address1, address0, text, True, 10, True)
        assert(ro['result'] == 'Not Sent.')
        assert(isclose(ro['fee'], 0.00186600))


        self.sync_all()

        self.stakeBlocks(1)
        assert(nodes[0].smsggetfeerate() == 61939)

        self.waitForSmsgExchange(1, 1, 0)

        ro = nodes[0].smsginbox('all')
        assert(len(ro['messages']) == 1)
        assert(ro['messages'][0]['text'] == text)


if __name__ == '__main__':
    SmsgPaidFeeExtTest().main()
