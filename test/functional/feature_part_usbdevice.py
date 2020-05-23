#!/usr/bin/env python3
# Copyright (c) 2018-2020 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import json
import configparser

from test_framework.test_ghost import (
    GhostTestFramework,
    isclose,
    getIndexAtProperty,
    connect_nodes_bi,
)
from test_framework.test_framework import SkipTest
from test_framework.util import assert_raises_rpc_error
from test_framework.authproxy import JSONRPCException


class USBDeviceTest(GhostTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [ ['-debug','-noacceptnonstdtxn','-reservebalance=10000000', '-txindex'] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 1, 2)
        self.sync_all()

    def run_test(self):

        # Check that ghost has been built with USB device enabled
        config = configparser.ConfigParser()
        if not self.options.configfile:
            self.options.configfile = os.path.dirname(__file__) + "/../config.ini"
        config.read_file(open(self.options.configfile))

        if not config["components"].getboolean("ENABLE_USBDEVICE"):
            raise SkipTest("ghostd has not been built with usb device enabled.")

        nodes = self.nodes

        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)

        ro = nodes[1].listdevices()
        assert(len(ro) == 1)
        assert(ro[0]['vendor'] == 'Debug')
        assert(ro[0]['product'] == 'Device')

        ro = nodes[1].getdeviceinfo()
        assert(ro['device'] == 'debug')

        ro = nodes[1].getdevicepublickey('0')
        assert(ro['address'] == 'praish9BVxVdhykpqBYEs6L65AQ7iKd9z1')
        assert(ro['path'] == "m/44'/1'/0'/0")

        ro = nodes[1].getdevicepublickey('0/1')
        assert(ro['address'] == 'peWvjy33QptC2Gz3ww7jTTLPjC2QJmifBR')
        assert(ro['path'] == "m/44'/1'/0'/0/1")

        ro = nodes[1].getdevicexpub("m/44'/1'/0'", "")
        assert(ro == 'pparszKXPyRegWYwPacdPduNPNEryRbZDCAiSyo8oZYSsbTjc6FLP4TCPEX58kAeCB6YW9cSdR6fsbpeWDBTgjbkYjXCoD9CNoFVefbkg3exzpQE')

        message = 'This is just a test message'
        sig = nodes[1].devicesignmessage('0/1', message)
        assert(True == nodes[1].verifymessage('peWvjy33QptC2Gz3ww7jTTLPjC2QJmifBR', sig, message))

        ro = nodes[1].initaccountfromdevice('test_acc')
        assert(ro['extkey'] == 'pparszKXPyRegWYwPacdPduNPNEryRbZDCAiSyo8oZYSsbTjc6FLP4TCPEX58kAeCB6YW9cSdR6fsbpeWDBTgjbkYjXCoD9CNoFVefbkg3exzpQE')
        assert(ro['path'] == "m/44'/1'/0'")

        ro = nodes[1].extkey('list', 'true')
        assert(len(ro) == 1)
        assert(ro[0]['path'] == "m/44h/1h/0h")
        assert(ro[0]['epkey'] == 'pparszKXPyRegWYwPacdPduNPNEryRbZDCAiSyo8oZYSsbTjc6FLP4TCPEX58kAeCB6YW9cSdR6fsbpeWDBTgjbkYjXCoD9CNoFVefbkg3exzpQE')
        assert(ro[0]['label'] == 'test_acc')
        assert(ro[0]['hardware_device'] == '0xffff 0x0001')

        ro = nodes[1].extkey('account')
        n = getIndexAtProperty(ro['chains'], 'use_type', 'stealth_spend')
        assert(n > -1)
        assert(ro['chains'][n]['path'] == "m/0h/444445h")


        addr1_0 = nodes[1].getnewaddress('lbl1_0')
        ro = nodes[1].filteraddresses()
        assert(len(ro) == 1)
        assert(ro[0]['path'] == 'm/0/0')
        assert(ro[0]['owned'] == 'true')
        assert(ro[0]['label'] == 'lbl1_0')

        va_addr1_0 = nodes[1].getaddressinfo(addr1_0)
        assert(va_addr1_0['ismine'] == True)
        assert(va_addr1_0['iswatchonly'] == False)
        assert(va_addr1_0['isondevice'] == True)
        assert(va_addr1_0['path'] == 'm/0/0')

        try:
            nodes[1].getnewstealthaddress()
            raise AssertionError('Should have failed.')
        except JSONRPCException as e:
            pass

        extaddr1_0 = nodes[1].getnewextaddress()

        txnid0 = nodes[0].sendtoaddress(addr1_0, 6)
        txnid1 = nodes[0].sendtoaddress(extaddr1_0, 6)

        self.stakeBlocks(1)
        block_txns = nodes[0].getblock(nodes[0].getblockhash(nodes[0].getblockcount()))['tx']
        assert(txnid0 in block_txns)
        assert(txnid1 in block_txns)

        ro = nodes[1].getwalletinfo()
        assert(isclose(ro['balance'], 12.0))

        addr0_0 = nodes[0].getnewaddress()
        hexRaw = nodes[1].createrawtransaction([], {addr0_0:10})
        hexFunded = nodes[1].fundrawtransaction(hexRaw)['hex']
        txDecoded = nodes[1].decoderawtransaction(hexFunded)

        ro = nodes[1].devicesignrawtransaction(hexFunded)
        assert(ro['complete'] == True)

        txnid1 = nodes[1].sendrawtransaction(ro['hex'])

        self.sync_all()
        self.stakeBlocks(1)

        ro = nodes[1].devicesignrawtransaction(hexFunded)
        assert(ro['errors'][0]['error'] == 'Input not found or already spent')

        prevtxns = []
        for vin in txDecoded['vin']:
            rtx = nodes[1].getrawtransaction(vin['txid'], True)
            prev_out = rtx['vout'][vin['vout']]
            prevtxns.append({'txid': vin['txid'], 'vout': vin['vout'], 'scriptPubKey': prev_out['scriptPubKey']['hex'], 'amount': prev_out['value']})
        ro = nodes[1].devicesignrawtransaction(hexFunded, prevtxns, ['0/0', '2/0'])
        assert(ro['complete'] == True)

        ro = nodes[1].listunspent()
        assert(ro[0]['ondevice'] == True)

        txnid2 = nodes[1].sendtoaddress(addr0_0, 0.1)

        self.sync_all()
        nodes[0].syncwithvalidationinterfacequeue()
        assert(nodes[0].filtertransactions()[0]['txid'] == txnid2)

        hwsxaddr = nodes[1].devicegetnewstealthaddress()
        assert(hwsxaddr == 'tps1qqpdwu7gqjqz9s9wfek843akvkzvw0xq3tkzs93sj4ceq60cp54mvzgpqf4tp6d7h0nza2xe362am697dax24hcr33yxqwvq58l5cf6j6q5hkqqqgykgrc')

        hwsxaddr2 = nodes[1].devicegetnewstealthaddress('lbl2 4bits', '4', '0xaaaa', True)
        assert(hwsxaddr2 == 'tps1qqpewyspjp93axk82zahx5xfjyprpvypfgnp95n9aynxxw3w0qs63acpq0s5z2rwk0raczg8jszl9qy5stncud76ahr5etn9hqmp30e3e86w2qqypgh9sgv0')

        ro = nodes[1].getaddressinfo(hwsxaddr2)
        assert(ro['prefix_num_bits'] == 4)
        assert(ro['prefix_bitfield'] == '0x000a')
        assert(ro['isondevice'] == True)

        ro = nodes[1].liststealthaddresses()
        assert(len(ro[0]['Stealth Addresses']) == 2)


        ro = nodes[1].filteraddresses()
        assert(len(ro) == 3)


        txnid3 = nodes[0].sendtoaddress(hwsxaddr, 0.1, '', '', False, 'test msg')
        self.stakeBlocks(1)

        ro = nodes[1].listtransactions()
        assert(len(ro) == 5)
        assert('test msg' in self.dumpj(ro[4]))

        ro = nodes[1].listunspent()
        inputs = []
        for output in ro:
            if output['txid'] == txnid3:
                inputs.append({'txid' : txnid3, 'vout' : output['vout']})
                break
        assert(len(inputs) > 0)
        hexRaw = nodes[1].createrawtransaction(inputs, {addr0_0:0.09})

        ro = nodes[1].devicesignrawtransaction(hexRaw)
        assert(ro['complete'] == True)

        # import privkey in node2
        rootkey = nodes[2].extkeyaltversion('xparFdrwJK7K2nfYzrkEqAKr5EcJNdY4c6ZNoLFFx1pMXQSQpo5MAufjogrS17RkqsLAijZJaBDHhG3G7SuJjtsTmRRTEKZDzGMnVCeX59cQCiR')
        ro = nodes[2].extkey('import', rootkey, 'master key', True)
        ro = nodes[2].extkey('setmaster', ro['id'])
        assert(ro['result'] == 'Success.')
        ro = nodes[2].extkey('deriveaccount', 'test account')
        ro = nodes[2].extkey('setdefaultaccount', ro['account'])
        assert(ro['result'] == 'Success.')

        ro = nodes[1].extkey('account')
        n = getIndexAtProperty(ro['chains'], 'use_type', 'stealth_spend')
        assert(n > -1)
        assert(ro['chains'][n]['path'] == "m/0h/444445h")

        addrtest = nodes[2].getnewaddress()
        ro = nodes[1].getdevicepublickey('0/0')
        assert(addrtest == ro['address'])


        addrtest = nodes[2].getnewstealthaddress('', '0', '', True, True)
        assert(addrtest == hwsxaddr)

        addrtest2 = nodes[2].getnewstealthaddress('lbl2 4bits', '4', '0xaaaa', True, True)
        assert(addrtest2 == hwsxaddr2)

        extaddr2_0 = nodes[2].getnewextaddress()
        assert(extaddr1_0 == extaddr2_0)

        # Ensure account matches after node restarts
        account1 = nodes[1].extkey('account')
        self.restart_node(1)
        account1_r = nodes[1].extkey('account')
        assert(json.dumps(account1) == json.dumps(account1_r))

        # Test for coverage
        assert(nodes[1].promptunlockdevice()['sent'] is True)
        assert(nodes[1].unlockdevice('123')['unlocked'] is True)
        assert_raises_rpc_error(-8, 'Neither a pin nor a passphraseword was provided.', nodes[1].unlockdevice)
        assert('complete' in nodes[1].devicebackup())
        assert('complete' in nodes[1].deviceloadmnemonic())


if __name__ == '__main__':
    USBDeviceTest().main()
