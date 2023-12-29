# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

from io import BytesIO

from .base58 import base58
from .util import int_to_big_endian, big_endian_to_int, int_to_little_endian,\
    little_endian_to_int
from .hash import hmac_sha512, hash160
from .network import Network
from .ecc import PubKey, PrivKey

class ExtendedKey:
    def __init__(self, \
        key, chain_code: bytes, \
        network: str = 'mainnet', \
        depth: int = 0,\
        parent: bytes = bytes.fromhex('00000000'),\
        index: int = 0):

        if not (isinstance(key, PrivKey) or isinstance(key, PubKey)):
            raise ValueError(\
                'Key is neither a PrivKey nor a PubKey, type: {}'.format(\
                    type(self.key)))

        self.key = key
        self.chain_code = chain_code
        self.network = network
        self.depth = depth
        self.parent = parent
        self.index = index

    def __eq__(self, other):
        return self.key == other.key and self.chain_code == other.chain_code \
            and self.network == other.network and self.depth == other.depth \
            and self.parent == other.parent and self.index == other.index

    @classmethod
    def from_seed(cls, seed: bytes):
        my_data = seed
        my_key = 'Bitcoin seed'.encode()
        k = hmac_sha512(my_key, my_data)
        key = PrivKey(big_endian_to_int(k[:32]))
        chain_code = k[32:]
        return cls(key, chain_code)

    def serialize(self):
        '''
        Serialize to a binary representation.
        '''
        key_ser = self.key.serialize()
        if len(key_ser)==32:
            key_ser = bytes.fromhex('00') + key_ser
        assert len(key_ser)==33

        if isinstance(self.key, PrivKey):
            version = Network.hdwallet_priv_prefix(self.network)
        elif isinstance(self.key, PubKey):
            version = Network.hdwallet_pub_prefix(self.network)
        else:
            raise ValueError(\
                'Key is neither a PrivKey nor a PubKey, type: {}'.format(\
                    type(self.key)))

        key78 = version \
            + int_to_big_endian(self.depth, 1) \
            + self.parent \
            + int_to_big_endian(self.index, 4) \
            + self.chain_code \
            + key_ser
        return key78

    def hex(self):
        return self.serialize().hex()

    @classmethod
    def parse(cls, stream):
        '''
        Parse from binary representation.
        '''
        version = stream.read(4)
        depth = big_endian_to_int(stream.read(1))
        parent = stream.read(4)
        index = big_endian_to_int(stream.read(4))
        chain_code = stream.read(32)
        key_ser = stream.read(33)

        assert len(key_ser)==33

        if version == Network.hdwallet_priv_prefix('testnet'):
            network = 'testnet'
            is_private = True
        elif version == Network.hdwallet_priv_prefix('mainnet'):
            network = 'mainnet'
            is_private = True
        elif version == Network.hdwallet_pub_prefix('mainnet'):
            network = 'mainnet'
            is_private = False
        elif version == Network.hdwallet_pub_prefix('testnet'):
            network = 'testnet'
            is_private = False
        else:
            raise ValueError('Unknown hdwallet prefix')

        if is_private:
            assert key_ser[0]==0
            key = PrivKey.parse(key_ser[1:])
        else:
            key = PubKey.parse(key_ser)

        if depth==0:
            assert index==0
            assert parent == bytes.fromhex('00000000')

        return cls(key, chain_code, network, depth, parent, index)

    def __repr__(self):
        return self.write()

    @classmethod
    def read(cls, string):
        '''
        Parse from human readable format
        '''
        data = base58.decode_checksum(string)
        return cls.parse(BytesIO(data))

    def write(self):
        '''
        Write to human readable format
        '''
        return base58.encode_checksum(self.serialize())


    def neutered(self):
        assert isinstance(self.key, PrivKey)
        return self.__class__(self.key.PubKey(), self.chain_code, self.network, self.depth,\
            self.parent, self.index)

    def fingerprint(self):
        pk = None
        if isinstance(self.key, PubKey):
            pk = self.key
        elif isinstance(self.key, PrivKey):
            pk = self.key.PubKey()
        return hash160(pk.serialize())[:4]

    def is_public(self):
        return isinstance(self.key, PubKey)

    def CDK(self, index, hardened=False):
        if hardened:
            index += 2**31
        key = None
        chain_code = None
        if isinstance(self.key, PubKey):
            if hardened:
                raise ValueError('A hardened key cannot be derived from a PubKey')
            else:
                pk = self.key
                data = hmac_sha512(self.chain_code, pk.serialize() +
                    int_to_big_endian(index, 4))
                key = PrivKey(big_endian_to_int(data[:32])).PubKey() + self.key
                chain_code = data[32:]
        elif isinstance(self.key, PrivKey):
            if hardened:
                data = hmac_sha512(self.chain_code, bytes.fromhex('00') \
                    + self.key.serialize() \
                    + int_to_big_endian(index, 4))
                key = PrivKey(big_endian_to_int(data[:32])) + self.key
                chain_code = data[32:]
            else:
                pk = self.key.PubKey()
                data = hmac_sha512(self.chain_code, pk.serialize() +
                    int_to_big_endian(index, 4))
                key = PrivKey(big_endian_to_int(data[:32])) + self.key
                chain_code = data[32:]
        return self.__class__(key, chain_code, self.network, self.depth+1,\
            self.fingerprint(), index)
