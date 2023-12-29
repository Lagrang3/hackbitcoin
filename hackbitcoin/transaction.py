# Bitcoin transactions

from io import BytesIO

from .util import little_endian_to_int, int_to_little_endian
from .varint import varint
from .rpc import bitcoin_RPC
from .script import Script
from .hash import double_sha256, sha256
from .witness import Witness

class TxIn:
    def __init__(self,prev_tx,prev_index,script_sig,sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        self._script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(self.prev_tx.hex(),self.prev_index)

    def serialize(self):
        data = self.prev_tx[::-1] \
            + int_to_little_endian(self.prev_index,4)
        data += self._script_sig.serialize()
        data += int_to_little_endian(self.sequence,4)
        return data

    def serialize_sighash(self, include_scriptpubkey: bool = False):
        data = self.prev_tx[::-1] \
            + int_to_little_endian(self.prev_index,4)
        if include_scriptpubkey:
            data += self.script_pubkey().serialize()
        else:
            data += varint.encode(0)
        data += int_to_little_endian(self.sequence,4)
        return data

    @classmethod
    def parse(cls,stream):
        prev_tx = stream.read(32)[::-1]
        prev_index = little_endian_to_int(stream.read(4))
        script_sig = Script.parse(stream)
        sequence = little_endian_to_int(stream.read(4))
        return cls(prev_tx,prev_index,script_sig,sequence)

    def fetch_tx(self, network='mainnet'):
        '''Get me the transaction that this input is refering to.'''
        return TxFetcher.fetch(self.prev_tx.hex(), network=network)

    def value(self, network='mainnet'):
        '''How much is this input worth?'''
        tx = self.fetch_tx(network=network)
        return tx.tx_outs[self.prev_index].amount_sats

    def script_pubkey(self, network='mainnet'):
        '''Get me the lock script that we spend with this TxIn'''
        tx = self.fetch_tx(network=network)
        pk = tx.tx_outs[self.prev_index].script_pubkey
        print('prev tx scriptPubKey:', pk.hex())
        return tx.tx_outs[self.prev_index].script_pubkey

    def script_sig(self):
        return self._script_sig

class TxOut:
    def __init__(self,amount_sats,script_pubkey):
        self.amount_sats = amount_sats
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}:{}'.format(self.amount_sats,self.script_pubkey)

    def serialize(self):
        return int_to_little_endian(self.amount_sats,8) \
            + self.script_pubkey.serialize()

    @classmethod
    def parse(cls,stream):
        amount_sats = little_endian_to_int(stream.read(8))
        script_pubkey = Script.parse(stream)
        return cls(amount_sats,script_pubkey)


class Tx:
    """Bitcoin transaction, see https://en.bitcoin.it/wiki/Transaction"""
    def __init__(self,version,tx_ins,tx_outs,locktime, witness = None, network='mainnet'):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.network = network
        self.witness = witness

    def is_segwit(self):
        '''Is this a segwit transaction?'''
        return not (self.witness is None)

    def __repr__(self):
        """Human readable transaction."""
        tx_ins = ''
        for i in self.tx_ins:
            tx_ins += i.__repr__() + '\n'
        tx_outs = ''
        for o in self.tx_outs:
            tx_outs += o.__repr__() + '\n'
        return 'tx: {}\nversion {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
            self.txid(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime
        )


    def txid(self):
        """Hexadecimal representation of the serialized transaction without
        witness hash"""
        return double_sha256(self.stripped_serialize())[::-1].hex()

    def wtxid(self):
        """Hexadecimal representation of the serialized transaction (witness
        included) hash"""
        return self.hash().hex()

    def stripped_serialize(self):
        '''Witness is segregated.
        [version][N inputs][N outputs][locktime]
        [4 bytes][vector  ][vector   ][4 bytes ]
        '''
        tx_in_data = varint.encode(len(self.tx_ins))
        for tx in self.tx_ins:
            tx_in_data += tx.serialize()

        tx_out_data = varint.encode(len(self.tx_outs))
        for tx in self.tx_outs:
            tx_out_data += tx.serialize()

        data = int_to_little_endian(self.version,4) \
            + tx_in_data + tx_out_data \
            + int_to_little_endian(self.locktime,4)
        return data


    def serialize(self):
        '''Entire transaction serialization, witness included.
        [version][witness flag][N inputs][N outputs][witness data][locktime]
        [4 bytes][2 bytes     ][vector  ][vector   ][vector      ][4 bytes ]
        '''
        tx_in_data = varint.encode(len(self.tx_ins))
        for tx in self.tx_ins:
            tx_in_data += tx.serialize()

        tx_out_data = varint.encode(len(self.tx_outs))
        for tx in self.tx_outs:
            tx_out_data += tx.serialize()

        witness_flag = b''
        witness_data = b''
        if self.is_segwit():
            # TODO: a segwit version is needed
            witness_flag = b'\x00\x01'
            witness_data = self.witness.serialize()

        data = int_to_little_endian(self.version,4) \
            + witness_flag \
            + tx_in_data + tx_out_data \
            + witness_data \
            + int_to_little_endian(self.locktime,4)
        return data

    def size(self):
        return len(self.serialize())

    def vsize(self):
        return int((self.weight() + Witness.WITNESS_SCALE_FACTOR - 1)/Witness.WITNESS_SCALE_FACTOR)

    def weight(self):
        '''
        See bitcoin/bitcoin/src/consensus/validation.h GetTransactionWeight
        '''
        return len(self.stripped_serialize())*(Witness.WITNESS_SCALE_FACTOR - 1) \
            + self.size()

    def hash(self):
        '''Hash with segregated witness'''
        # result in little-endian
        return double_sha256(self.serialize())[::-1]


    @classmethod
    def parse(cls,stream):
        version = little_endian_to_int(stream.read(4))
        # Miner compatibility: see https://bitcoin.stackexchange.com/questions/60368/can-a-non-segwit-miner-mine-segwit-transactions

        n_inputs = 0
        witness_flag = 0

        witness_marker = varint.parse(stream)
        if witness_marker==0:
            witness_flag = little_endian_to_int(stream.read(1))
            if witness_flag!=1:
                # TODO: witness version handling
                raise RuntimeError(
                    'Witness flag 0x01 expected, instead {} was found'.format(
                        witness_flag))
            n_inputs = varint.parse(stream)
        else:
            n_inputs = witness_marker

        assert n_inputs>=1

        inputs = []
        for i in range(n_inputs):
            inputs.append(TxIn.parse(stream))
        n_outputs = varint.parse(stream)
        outputs = []
        for i in range(n_outputs):
            outputs.append(TxOut.parse(stream))

        witness=None
        if witness_flag!=0:
            witness = Witness.parse(stream, n_inputs)

        locktime = little_endian_to_int(stream.read(4))
        return cls(version,inputs,outputs,locktime,witness)

    def is_coinbase(self):
        # FIXME: is this how we define a coinbase transaction?
        if len(self.tx_ins)==1 and self.tx_ins[0].prev_tx.hex()==64*'0' \
            and self.tx_ins[0].prev_index == 0xffffffff:
            return True
        return False


    def fee(self, network='mainnet'):
        if self.is_coinbase():
            return 0

        sins = 0
        for tx in self.tx_ins:
            sins += tx.value(network)
        souts = 0
        for tx in self.tx_outs:
            souts += tx.amount_sats
        if sins < souts:
            raise ValueError('Transaction outputs are greater than the inputs.')
        return sins - souts

    def feerate(self, network='mainnet'):
        fee = self.fee()
        vsize = self.vsize()
        # TODO: is this how feerate is defined?
        return int((fee+vsize-1)/vsize)

    def sighash(self, sighash_flag: int, index: int):
        if not sighash_flag in [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]:
            raise ValueError('invalid sighash flag 0x{:x}'.format(sighash_flag))
        ANYONECANPAY = bool(sighash_flag & 0x80)
        OUTBITS = sighash_flag & 0x0f

        # serialize the transaction without scriptSig
        data = int_to_little_endian(self.version,4)

        if ANYONECANPAY:
            # no inputs are signed
            print("Sighash ANYONECANPAY")
            data += varint.encode(0)
        else:
            # all inputs are signed
            data += varint.encode(len(self.tx_ins))
            for i, txi in enumerate(self.tx_ins):
                include_scriptpubkey = bool(i==index)
                print("input number {}, include_scriptpubkey: {}".format(i, \
                    include_scriptpubkey))
                data += txi.serialize_sighash(include_scriptpubkey=include_scriptpubkey)

        if OUTBITS==0x01: # ALL
            print("Sighash ALL")
            print("number of outputs:", len(self.tx_outs))
            # all outputs are signed
            data += varint.encode(len(self.tx_outs))
            for txo in self.tx_outs:
                data += txo.serialize()
        elif OUTBITS==0x03: # SINGLE
            # only one output is signed
            data += varint.encode(1)
            data += self.tx_outs[index].serialize()
        else: # OUTBITS==0x02: # NONE
            # no outputs are signed
            data += varint.encode(0)

        data += int_to_little_endian(self.locktime, 4)
        data += int_to_little_endian(sighash_flag, 4)
        h = double_sha256(data)
        print("raw tx to sign:", data.hex())
        print("sha256^2:", h.hex())
        return h
        # return sha256(data)

    def is_valid(self, ignore_utxos = True):
        if self.fee()<0:
            return False
        for i,txi in enumerate(self.tx_ins):
            # verify script or witness
            if self.is_segwit():
                # TODO
                pass
            else:
                scriptpubkey = txi.script_pubkey()
                scriptsig = txi.script_sig()
                combined = scriptsig + scriptpubkey
                def sighash_getter(sighash_flag):
                    print("sighash flag is: 0x{:x}".format(sighash_flag))
                    return self.sighash(sighash_flag,i)
                if not combined.evaluate(sighash_getter):
                    print("script evaluation failed:", combined.debug_message)
                    return False

            # are these inputs unspent?
            if not ignore_utxos:
                # TODO
                pass
        return True


class TxFetcher:
    cache = {}

    @classmethod
    def add_to_cache(cls, tx):
        tx_id = tx.txid()
        if tx_id not in cls.cache:
            cls.cache[tx_id] = tx

    @classmethod
    def fetch(cls, tx_id, network='mainnet'):
        if tx_id not in cls.cache:
            response = bitcoin_RPC.request('getrawtransaction',
                                            params={'txid':tx_id},
                                            network=network)
            raw = bytes.fromhex(response)
            tx = Tx.parse(BytesIO(raw))

            if tx.txid() != tx_id:
                raise ValueError('not the same id: {} vs {}'.format(tx.txid(),tx_id))
            cls.cache[tx_id] = tx
        return cls.cache[tx_id]
