#!/usr/bin/env python3
# Copyright (C) 2017-2019 The Particl Core developers
# Copyright (C) 2020 The Ghost Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time
import json
import decimal

from .test_framework import BitcoinTestFramework
from .util import assert_equal, coverage, connect_nodes


def isclose(a, b, rel_tol=1e-09, abs_tol=0.0):
    a = decimal.Decimal(a)
    b = decimal.Decimal(b)
    return abs(a-b) <= max(decimal.Decimal(rel_tol) * decimal.Decimal(max(abs(a), abs(b))), abs_tol)

def connect_nodes_bi(nodes, a, b):
    connect_nodes(nodes[a], b)
    connect_nodes(nodes[b], a)

def getIndexAtProperty(arr, name, value):
    for i, o in enumerate(arr):
        try:
            if o[name] == value:
                return i
        except:
            continue
    return -1


class GhostTestFramework(BitcoinTestFramework):
    def start_node(self, i, *args, **kwargs):
        kwargs['btcmode'] = False
        return super().start_node(i, *args, **kwargs)

    def start_nodes(self, extra_args=None, *args, **kwargs):
        """Start multiple bitcoinds"""
        kwargs['btcmode'] = False
        if extra_args is None:
            extra_args = [None] * self.num_nodes
        assert_equal(len(extra_args), self.num_nodes)
        try:
            for i, node in enumerate(self.nodes):
                node.start(extra_args[i], *args, **kwargs)
            for node in self.nodes:
                node.wait_for_rpc_connection()
        except:
            # If one node failed to start, stop the others
            self.stop_nodes()
            raise

        if self.options.coveragedir is not None:
            for node in self.nodes:
                coverage.write_all_rpc_commands(self.options.coveragedir, node.rpc)

    def wait_for_height(self, node, nHeight, nTries=500):
        for i in range(nTries):
            time.sleep(1)
            ro = node.getblockchaininfo()
            if ro['blocks'] >= nHeight:
                return True
        return False

    def wait_for_mempool(self, node, txnHash, nTries=50):
        for i in range(50):
            time.sleep(0.5)
            try:
                ro = node.getmempoolentry(txnHash)

                if ro['vsize'] >= 100 and ro['height'] >= 0:
                    return True
            except:
                continue
        return False

    def waitForSmsgExchange(self, nMessages, nodeA, nodeB):
        nodes = self.nodes

        fPass = False
        for i in range(30):
            time.sleep(0.5)
            ro = nodes[nodeA].smsgbuckets()
            if ro['total']['messages'] == nMessages:
                fPass = True
                break
        assert(fPass)

        fPass = False
        for i in range(30):
            time.sleep(0.5)
            ro = nodes[nodeB].smsgbuckets()
            if ro['total']['messages'] == nMessages:
                fPass = True
                break
        assert(fPass)

    def stakeToHeight(self, height, fSync=True, nStakeNode=0, nSyncCheckNode=1):
        self.nodes[nStakeNode].walletsettings('stakelimit', {'height':height})
        self.nodes[nStakeNode].reservebalance(False)
        assert(self.wait_for_height(self.nodes[nStakeNode], height))
        self.nodes[nStakeNode].reservebalance(True, 10000000)
        if not fSync:
            return
        self.sync_all()
        assert(self.nodes[nSyncCheckNode].getblockcount() == height)

    def stakeBlocks(self, nBlocks, nStakeNode=0, fSync=True):
        height = self.nodes[nStakeNode].getblockcount()

        self.stakeToHeight(height + nBlocks, fSync=fSync, nStakeNode=nStakeNode)

    def jsonDecimal(self, obj):
        if isinstance(obj, decimal.Decimal):
            return str(obj)
        raise TypeError

    def dumpj(self, obj):
        return json.dumps(obj, indent=4, default=self.jsonDecimal)

    def set_test_params(self):
        """Tests must this method to change default values for number of nodes, topology, etc"""
        raise NotImplementedError

    def run_test(self):
        """Tests must override this method to define test logic"""
        raise NotImplementedError
