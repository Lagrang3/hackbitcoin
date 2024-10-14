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
    def p2sh(script_hash, network='mainnet'):
        prefix = Network.address_prefix('P2SH', network)
        return base58.encode_checksum(prefix+script_hash)

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

    @staticmethod
    def address(pubkey, scheme, network='mainnet'):
        if scheme=='P2PKH':
            return Address.p2pkh(pubkey, network)
        if scheme=='P2WPKH':
            return Address.p2wpkh(pubkey, network)
        if scheme == 'P2SH(P2WPKH)':
            pk_hash = hash160(pubkey.serialize())
            script = Script.from_opcodes([ \
                    Script.OP_0, pk_hash])
            script_hash = hash160(script.serialize()[1:])
            return Address.p2sh(script_hash, network)
        if scheme == 'P2SH(P2PKH)':
            pk_hash = hash160(pubkey.serialize())
            script = Script.from_opcodes([ \
                    Script.OP_DUP, Script.OP_HASH160, pk_hash,
                    Script.OP_EQUALVERIFY, Script.OP_CHECKSIG])
            script_hash = hash160(script.serialize()[1:])
            return Address.p2sh(script_hash, network)
        raise RuntimeError("not a valid scheme")
