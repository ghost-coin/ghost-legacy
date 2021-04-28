#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import random
from test_framework.test_particl import ParticlTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.address import base58_to_byte
from test_framework.key import SECP256K1, ECPubKey
from test_framework.messages import sha256


class AnonTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [ ['-debug','-noacceptnonstdtxn','-reservebalance=10000000'] for i in range(self.num_nodes)]

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
        txnHashes = []

        nodes[1].extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate')
        sxAddrTo1_1 = nodes[1].getnewstealthaddress('lblsx11')
        assert(sxAddrTo1_1 == 'TetbYTGv5LiqyFiUD3a5HHbpSinQ9KiRYDGAMvRzPfz4RnHMbKGAwDr1fjLGJ5Eqg1XDwpeGyqWMiwdK3qM3zKWjzHNpaatdoHVzzA')

        nodes[2].extkeyimportmaster(nodes[2].mnemonic('new')['master'])

        sxAddrTo0_1 = nodes[0].getnewstealthaddress('lblsx01')

        txnHashes.append(nodes[0].sendparttoanon(sxAddrTo1_1, 1, '', '', False, 'node0 -> node1 p->a'))
        txnHashes.append(nodes[0].sendparttoblind(sxAddrTo0_1, 1000, '', '', False, 'node0 -> node0 p->b'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 1'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 2'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 3'))
        txnHashes.append(nodes[0].sendblindtoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 b->a 4'))

        for k in range(5):
            txnHash = nodes[0].sendparttoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 p->a')
            txnHashes.append(txnHash)
        for k in range(10):
            txnHash = nodes[0].sendblindtoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 b->a')
            txnHashes.append(txnHash)

        for h in txnHashes:
            assert(self.wait_for_mempool(nodes[1], h))

        assert('node0 -> node1 b->a 4' in self.dumpj(nodes[1].listtransactions('*', 100)))
        assert('node0 -> node1 b->a 4' in self.dumpj(nodes[0].listtransactions('*', 100)))

        self.stakeBlocks(2)

        block1_hash = nodes[1].getblockhash(1)
        ro = nodes[1].getblock(block1_hash)
        for txnHash in txnHashes:
            assert(txnHash in ro['tx'])

        txnHash = nodes[1].sendanontoanon(sxAddrTo0_1, 1, '', '', False, 'node1 -> node0 a->a')
        txnHashes = [txnHash,]

        assert(self.wait_for_mempool(nodes[0], txnHash))
        self.stakeBlocks(1)

        ro = nodes[1].getblock(nodes[1].getblockhash(3))
        for txnHash in txnHashes:
            assert(txnHash in ro['tx'])

        assert(nodes[1].anonoutput()['lastindex'] == 28)

        txnHashes.clear()
        txnHashes.append(nodes[1].sendanontoanon(sxAddrTo0_1, 101, '', '', False, 'node1 -> node0 a->a', 5, 1))
        txnHashes.append(nodes[1].sendanontoanon(sxAddrTo0_1, 0.1, '', '', False, '', 5, 2))

        assert(nodes[1].getwalletinfo()['anon_balance'] > 10)

        outputs = [{'address': sxAddrTo0_1, 'amount': 10, 'subfee': True},]
        ro = nodes[1].sendtypeto('anon', 'part', outputs, 'comment_to', 'comment_from', 4, 32, True)
        assert(ro['bytes'] > 0)

        txnHashes.append(nodes[1].sendtypeto('anon', 'part', outputs))
        txnHashes.append(nodes[1].sendtypeto('anon', 'anon', [{'address': sxAddrTo1_1, 'amount': 1},]))

        for txhash in txnHashes:
            assert(self.wait_for_mempool(nodes[0], txhash))

        self.log.info('Test filtertransactions with type filter')
        ro = nodes[1].filtertransactions({'type': 'anon', 'count': 20, 'show_anon_spends': True, 'show_change': True})
        assert(len(ro) > 2)
        foundTx = 0
        for t in ro:
            if t['txid'] == txnHashes[-1]:
                foundTx += 1
                assert(t['amount'] == t['fee'])
            elif t['txid'] == txnHashes[-2]:
                foundTx += 1
                assert('anon_inputs' in t)
                assert(t['amount'] < -9.9 and t['amount'] > -10.0)
                n_standard = 0
                n_anon = 0
                for to in t['outputs']:
                    if to['type'] == 'standard':
                        n_standard += 1
                    elif to['type'] == 'anon':
                        n_anon += 1
                        assert(to['is_change'] == 'true')
                assert(n_standard == 1)
                assert(n_anon > 0)
                assert(t['type_in'] == 'anon')
            if t['txid'] == txnHashes[-3]:
                foundTx += 1
                assert(t['outputs'][0]['type'] == 'anon')
            if foundTx > 2:
                break
        assert(foundTx > 2)

        self.log.info('Test unspent with address filter')
        unspent_filtered = nodes[1].listunspentanon(1, 9999, [sxAddrTo1_1])
        assert(unspent_filtered[0]['label'] == 'lblsx11')

        self.log.info('Test permanent lockunspent')

        unspent = nodes[1].listunspentanon()
        assert(nodes[1].lockunspent(False, [unspent[0]], True) == True)
        assert(nodes[1].lockunspent(False, [unspent[1]], True) == True)
        assert(len(nodes[1].listlockunspent()) == 2)
        # Restart node
        self.sync_all()
        self.stop_node(1)
        self.start_node(1, self.extra_args[1] + ['-wallet=default_wallet',])
        self.connect_nodes_bi(0, 1)
        assert(len(nodes[1].listlockunspent()) == 2)
        assert(len(nodes[1].listunspentanon()) < len(unspent))
        assert(nodes[1].lockunspent(True, [unspent[0]]) == True)
        assert_raises_rpc_error(-8, 'Invalid parameter, expected locked output', nodes[1].lockunspent, True, [unspent[0]])

        assert(len(nodes[1].listunspentanon()) == len(unspent)-1)
        assert(nodes[1].lockunspent(True) == True)
        assert(len(nodes[1].listunspentanon()) == len(unspent))
        assert(nodes[1].lockunspent(True) == True)

        ro = nodes[2].getblockstats(nodes[2].getblockchaininfo()['blocks'])
        assert(ro['height'] == 3)

        self.log.info('Test recover from mnemonic')
        # Txns currently in the mempool will be reprocessed in the next block
        self.stakeBlocks(1)
        wi_1 = nodes[1].getwalletinfo()

        nodes[1].createwallet('test_import')
        w1_2 = nodes[1].get_wallet_rpc('test_import')
        w1_2.extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate')
        w1_2.getnewstealthaddress('lblsx11')
        w1_2.rescanblockchain(0)
        wi_1_2 = w1_2.getwalletinfo()
        assert(wi_1_2['anon_balance'] == wi_1['anon_balance'])

        nodes[1].createwallet('test_import_locked')
        w1_3 = nodes[1].get_wallet_rpc('test_import_locked')
        w1_3.encryptwallet('test')

        assert_raises_rpc_error(-13, 'Error: Wallet locked, please enter the wallet passphrase with walletpassphrase first.', w1_3.filtertransactions, {'show_blinding_factors': True})
        assert_raises_rpc_error(-13, 'Error: Wallet locked, please enter the wallet passphrase with walletpassphrase first.', w1_3.filtertransactions, {'show_anon_spends': True})

        w1_3.walletpassphrase('test', 30)

        # Skip initial rescan by passing -1 as scan_chain_from
        w1_3.extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate',
            '', False, 'imported key', 'imported acc', -1)
        w1_3.getnewstealthaddress('lblsx11')
        w1_3.walletsettings('other', {'onlyinstance': False})
        w1_3.walletlock()
        assert(w1_3.getwalletinfo()['encryptionstatus'] == 'Locked')
        w1_3.rescanblockchain(0)

        w1_3.walletpassphrase('test', 30)

        wi_1_3 = w1_3.getwalletinfo()
        assert(wi_1_3['anon_balance'] == wi_1['anon_balance'])

        # Coverage
        w1_3.sendanontoblind(sxAddrTo0_1, 1.0)
        w1_3.sendanontopart(sxAddrTo0_1, 1.0)

        self.log.info('Test sendtypeto coincontrol')
        w1_inputs = w1_2.listunspentanon()
        assert(len(w1_inputs) > 1)
        use_input = w1_inputs[random.randint(0, len(w1_inputs) - 1)]

        coincontrol = {'inputs': [{'tx': use_input['txid'], 'n': use_input['vout']}]}
        txid = w1_2.sendtypeto('anon', 'anon', [{'address': sxAddrTo0_1, 'amount': 0.01}, ], '', '', 7, 1, False, coincontrol)

        w1_inputs_after = w1_2.listunspentanon()
        for txin in w1_inputs_after:
            if txin['txid'] == use_input['txid'] and txin['vout'] == use_input['vout']:
                raise ValueError('Output should be spent')

        assert(self.wait_for_mempool(nodes[1], txid))
        raw_tx = w1_2.getrawtransaction(txid, True)
        possible_inputs = raw_tx['vin'][0]['ring_row_0'].split(', ')
        possible_inputs_txids = []
        for pi in possible_inputs:
            anonoutput = w1_2.anonoutput(pi)
            possible_inputs_txids.append(anonoutput['txnhash'] + '.' + str(anonoutput['n']))
        assert(use_input['txid'] + '.' + str(use_input['vout']) in possible_inputs_txids)

        num_tries = 20
        for i in range(num_tries):
            if nodes[0].getbalances()['mine']['anon_immature'] == 0.0:
                break
            self.stakeBlocks(1)
            if i >= num_tries - 1:
                raise ValueError('anon balance immature')

        assert(nodes[0].getbalances()['mine']['anon_trusted'] > 100.0)

        self.log.info('Test crafting anon transactions.')
        sxAddr2_1 = nodes[2].getnewstealthaddress('lblsx01')

        ephem = nodes[0].derivefromstealthaddress(sxAddr2_1)
        blind = bytes(random.getrandbits(8) for i in range(32)).hex()
        outputs = [{
            'address': sxAddr2_1,
            'type': 'anon',
            'amount': 10.0,
            'blindingfactor': blind,
            'ephemeral_key': ephem['ephemeral_privatekey'],
        },]
        tx = nodes[0].createrawparttransaction([], outputs)

        options = {'sign_tx': True}
        tx_signed = nodes[0].fundrawtransactionfrom('anon', tx['hex'], {}, tx['amounts'], options)
        txid = nodes[0].sendrawtransaction(tx_signed['hex'])
        self.stakeBlocks(1)

        sx_privkey = nodes[2].dumpprivkey(sxAddr2_1)
        assert('scan_secret' in sx_privkey)
        assert('spend_secret' in sx_privkey)

        sx_pubkey = nodes[2].getaddressinfo(sxAddr2_1)
        assert('scan_public_key' in sx_pubkey)
        assert('spend_public_key' in sx_pubkey)

        stealth_key = nodes[2].derivefromstealthaddress(sxAddr2_1, ephem['ephemeral_pubkey'])

        prevtx = nodes[2].decoderawtransaction(tx_signed['hex'])
        found_output = -1
        for vout in prevtx['vout']:
            if vout['type'] != 'anon':
                continue
            try:
                ro = nodes[2].verifycommitment(vout['valueCommitment'], blind, 10.0)
                assert(ro['result'] is True)

                ro = nodes[2].rewindrangeproof(vout['rangeproof'], vout['valueCommitment'], stealth_key['privatekey'], ephem['ephemeral_pubkey'])
                assert(ro['amount'] == 10.0)
                found_output = vout['n']
            except Exception as e:
                print(e)
        assert(found_output > -1)

        key_bytes = base58_to_byte(stealth_key['privatekey'])[0][0:32]

        epk = ECPubKey()
        epk.set(bytes.fromhex(ephem['ephemeral_pubkey']))

        self.log.info('Test rewindrangeproof with final nonce')
        # ECDH
        P = SECP256K1.affine(epk.p)
        M = SECP256K1.affine(SECP256K1.mul([((P[0], P[1], P[2]), int.from_bytes(key_bytes, 'big'))]))
        eM = bytes([0x02 + (M[1] & 1)]) + M[0].to_bytes(32, 'big')
        hM = sha256(eM)
        hhM = sha256(hM)

        # Reverse, SetHex is LE
        hhM = hhM[::-1]

        vout = prevtx['vout'][found_output]
        ro = nodes[2].rewindrangeproof(vout['rangeproof'], vout['valueCommitment'], hhM.hex())
        assert(ro['amount'] == 10.0)

        self.log.info('Test signing for unowned anon input')  # Input not in wallet, must be in chain for pubkey index
        prev_tx_signed = nodes[0].decoderawtransaction(tx_signed['hex'])
        prev_commitment = prev_tx_signed['vout'][found_output]['valueCommitment']
        prev_public_key = prev_tx_signed['vout'][found_output]['pubkey']
        assert(prev_public_key == stealth_key['pubkey'])

        outputs = [{
            'address': sxAddr2_1,
            'type': 'anon',
            'amount': 10.0,
        },]
        tx = nodes[0].createrawparttransaction([], outputs)

        options = {
            'subtractFeeFromOutputs': [0,],
            'inputs': [{
                'tx': txid,
                'n': found_output,
                'type': 'anon',
                'value': 10.0,
                'commitment': prev_commitment,
                'pubkey': prev_public_key,
                'privkey': stealth_key['privatekey'],
                'blind': blind,
            }],
            'feeRate': 0.001,
            'sign_tx': True,
        }
        input_amounts = {
        }

        tx_signed = nodes[0].fundrawtransactionfrom('anon', tx['hex'], input_amounts, tx['amounts'], options)
        num_tries = 20
        for i in range(num_tries):
            try:
                txid = nodes[0].sendrawtransaction(tx_signed['hex'])
                break
            except Exception:
                self.stakeBlocks(1)
            if i >= num_tries - 1:
                raise ValueError('Can\'t submit txn')
        assert(self.wait_for_mempool(nodes[2], txid))

        self.stakeBlocks(1)
        w2b = nodes[2].getbalances()
        assert(w2b['mine']['anon_immature'] < 10 and w2b['mine']['anon_immature'] > 9)


if __name__ == '__main__':
    AnonTest().main()

