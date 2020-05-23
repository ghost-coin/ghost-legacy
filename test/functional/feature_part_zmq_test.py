#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Copyright (c) 2018-2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.z
"""Test the ZMQ API."""
import configparser
import os
import struct
import time
import base64

from test_framework.test_ghost import GhostTestFramework
from test_framework.test_framework import SkipTest


class ZMQTest(GhostTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        # Try to import python3-zmq. Skip this test if the import fails.
        try:
            import zmq
        except ImportError:
            raise SkipTest("python3-zmq module not available.")

        # Check that ghost has been built with ZMQ enabled
        config = configparser.ConfigParser()
        if not self.options.configfile:
            self.options.configfile = os.path.dirname(__file__) + "/../config.ini"
        config.read_file(open(self.options.configfile))

        if not config["components"].getboolean("ENABLE_ZMQ"):
            raise SkipTest("ghostd has not been built with zmq enabled.")

        self.zmq = zmq
        self.zmqContext = zmq.Context()
        self.zmqSubSocket = self.zmqContext.socket(zmq.SUB)

        self.zmqSubSocket.set(zmq.RCVTIMEO, 60000)
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtx")
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawblock")
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawtx")
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashwtx")
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"smsg")

        public_key, secret_key = self.zmq.curve_keypair()
        self.zmqSubSocket.setsockopt(zmq.CURVE_PUBLICKEY, public_key)
        self.zmqSubSocket.setsockopt(zmq.CURVE_SECRETKEY, secret_key)
        self.zmqSubSocket.setsockopt(zmq.CURVE_SERVERKEY, b"hn%V}2&Z$vWw!ugnb@[#)Lzfsiz(IY+U(EOTl#n&")

        ip_address = "tcp://127.0.0.1:28332"
        self.zmqSubSocket.connect(ip_address)

        server_secret = base64.b64encode(b"p%ymQKFW%l[45CJa}+y&<B%R]Q(MZ4G!lH3^H+y2").decode("utf-8")
        self.extra_args = [[
                        '-wallet=wallet_test',
                        '-serverkeyzmq=%s' % server_secret,
                        '-zmqpubhashblock=%s' % ip_address, '-zmqpubhashtx=%s' % ip_address,
                        '-zmqpubrawblock=%s' % ip_address, '-zmqpubrawtx=%s' % ip_address,
                        '-zmqpubsmsg=%s' % ip_address,
                        '-zmqpubhashwtx=%s' % ip_address],
                       []]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def run_test(self):
        try:
            self._zmq_test()
        finally:
            # Destroy the zmq context
            self.log.debug("Destroying zmq context")
            self.zmqContext.destroy(linger=None)

    def waitForZmqSmsg(self, msgid):
        for count in range(0, 100):
            try:
                msg = self.zmqSubSocket.recv_multipart(self.zmq.NOBLOCK)
            except self.zmq.ZMQError:
                time.sleep(0.25)
                continue

            topic = msg[0].decode('utf-8')
            if topic == 'smsg':
                fFound = True
                zmqhash = msg[1].hex()
                assert(zmqhash[:4] == '0300')  # version 3.0
                assert(zmqhash[4:] == msgid)
                return True
        return False

    def _zmq_test(self):
        nodes = self.nodes

        for i in range(len(nodes)):
            nodes[i].reservebalance(True, 10000000)

        nodes[0].extkeyimportmaster(nodes[0].mnemonic('new')['master'])
        nodes[1].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')

        addrTo = nodes[0].getnewaddress()
        txnHash = nodes[1].sendtoaddress(addrTo, 10)
        self.sync_all()

        self.log.info("Wait for tx")
        fFound = False
        fFoundWtx = False
        fFoundRawTx = False
        for count in range(0, 100):
            try:
                msg = self.zmqSubSocket.recv_multipart(self.zmq.NOBLOCK)
            except self.zmq.ZMQError:
                time.sleep(0.5)
                continue

            topic = msg[0].decode('utf-8')
            msgSequence = struct.unpack('<I', msg[-1])[-1]
            if topic == 'hashtx' and msgSequence == 1:
                fFound = True
                zmqhash = msg[1].hex()
                assert(zmqhash == txnHash)
            elif topic == 'rawtx' and msgSequence == 1:
                fFoundRawTx = True
                body = msg[1]
                # Check that the rawtx hashes to the hashtx
                #assert_equal(hash256(body), txnHash)
                #CTransaction.deserialize
            elif topic == 'hashwtx' and msgSequence == 0:
                fFoundWtx = True
                zmqhash = msg[1][0:32].hex()
                assert(zmqhash == txnHash)
                walletName = msg[1][32:].decode('utf-8')
                assert(walletName == 'wallet_test')

            if fFound and fFoundRawTx and fFoundWtx:
                break

        assert(fFound)
        assert(fFoundRawTx)
        assert(fFoundWtx)

        self.stakeBlocks(1, nStakeNode=1)
        self.log.info("Wait for block")
        fFound = False
        for count in range(0, 100):
            try:
                msg = self.zmqSubSocket.recv_multipart(self.zmq.NOBLOCK)
            except self.zmq.ZMQError:
                time.sleep(0.5)
                continue

            topic = msg[0].decode('utf-8')
            msgSequence = struct.unpack('<I', msg[-1])[-1]
            if topic == 'hashblock' and msgSequence == 0:
                fFound = True
                blkhash = msg[1].hex()
                besthash = nodes[1].getbestblockhash()
                assert(blkhash == besthash)
                break
        assert(fFound)

        address0 = nodes[0].getnewaddress()  # Will be different each run
        address1 = nodes[1].getnewaddress()
        assert(address1 == 'pX9N6S76ZtA5BfsiJmqBbjaEgLMHpt58it')

        ro = nodes[0].smsglocalkeys()
        assert(len(ro['wallet_keys']) == 0)

        ro = nodes[0].smsgaddlocaladdress(address0)  # Listen on address0
        assert('Receiving messages enabled for address' in ro['result'])

        ro = nodes[0].smsglocalkeys()
        assert(len(ro['wallet_keys']) == 1)

        ro = nodes[1].smsgaddaddress(address0, ro['wallet_keys'][0]['public_key'])
        assert(ro['result'] == 'Public key added to db.')


        ro = nodes[1].smsgsend(address1, address0, "['data':'test','value':1]", True, 4)
        msgid = ro['msgid']
        assert(ro['result'] == 'Sent.')

        self.stakeBlocks(1, nStakeNode=1)
        self.waitForSmsgExchange(1, 1, 0)

        assert(self.waitForZmqSmsg(msgid))

        ro = nodes[0].getnewzmqserverkeypair()
        assert(len(ro['server_secret_key']) == 40)
        assert(len(ro['server_public_key']) == 40)
        assert(len(ro['server_secret_key_b64']) > 40)

        ro = nodes[0].smsgzmqpush()
        assert(ro['numsent'] == 1)
        assert(self.waitForZmqSmsg(msgid))

        ro = nodes[0].smsgzmqpush({"timefrom": int(time.time()) + 1})
        assert(ro['numsent'] == 0)


if __name__ == '__main__':
    ZMQTest().main()
