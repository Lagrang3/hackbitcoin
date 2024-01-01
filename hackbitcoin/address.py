from .script import Script
from .hash import hash160
from .network import Network
from .base58 import base58
from .bech32 import encode as bech32_encode

class Address:
    @staticmethod
    def p2pkh(pubkey,network='mainnet'):
        h160 = hash160(pubkey.serialize())
        prefix = Network.address_prefix('P2PKH', network)
        return base58.encode_checksum(prefix+h160)

    @staticmethod
    def p2sh(pubkey,network='mainnet'):
        pk_hash = hash160(pubkey.serialize())
        script = Script.from_opcodes([ \
                Script.OP_DUP, Script.OP_HASH160, pk_hash,
                Script.OP_EQUALVERIFY, Script.OP_CHECKSIG])
        h160 = hash160(script.serialize())
        prefix = Network.address_prefix('P2SH', network)
        return base58.encode_checksum(prefix+h160)

    @staticmethod
    def p2wpkh(pubkey,network='mainnet'):
        '''Bitcoin segwit address'''
        h160 = hash160(pubkey.serialize())
        # TODO: segwit version and hrp
        segwit_version = 0
        if network=='mainnet':
            hrp = 'bc'
        elif network=='testnet':
            hrp = 'tb'
        else:
            raise ValueError('Network {} is not supported'.format(network))
        return bech32_encode(hrp,segwit_version,h160)

    @staticmethod
    def p2wsh_address(pubkey,network='mainnet'):
        # TODO
        pass

