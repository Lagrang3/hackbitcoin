#https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki

import base64

from hackbitcoin.hash import hmac_sha512, shake256
from hackbitcoin.bip39 import Mnemonic
from hackbitcoin.extkey import ExtendedKey
from hackbitcoin.ecc import PrivKey
from hackbitcoin.util import big_endian_to_int

class DRNG:
    '''
    Deterministic random number generator.
    '''
    def __init__(self, entropy: bytes):
        self.shake = shake256(entropy)
    def read(self, n):
        return self.shake.read(n)


class BIP85:
    '''
    Suite for deterministic entropy generation.
    '''

    @classmethod
    def entropy(cls, xpriv, path):
        '''
        Generator of deterministic entropy.
        '''
        derived = xpriv.derivation_path(path)
        entropy = hmac_sha512('bip-entropy-from-k'.encode(), derived.key.serialize())
        return entropy

    @classmethod
    def app_mnemonic(cls, xpriv, nwords: int, index: int):
        '''
        Generate a BIP39 mnemonic sentence.
        '''
        assert nwords==12 or nwords==15 or nwords==18 or nwords==21 or nwords==24
        entropy = cls.entropy(xpriv, "m/83696968'/39'/0'/{}'/{}'".format(nwords,index))
        MESS = nwords*11
        CS = MESS//33
        ENT = MESS - CS
        ENT_bytes = ENT//8
        entropy = entropy[:ENT_bytes]
        return Mnemonic.generate(entropy)

    @classmethod
    def app_hdseed(cls, xpriv, index: int):
        '''
        Generate a single private key.
        note: used in bitcoincore to generate the wallet.
        '''
        entropy = cls.entropy(xpriv, "m/83696968'/2'/{}'".format(index))[:32]
        key = PrivKey(secret = big_endian_to_int(entropy))
        return key


    @classmethod
    def app_xpriv(cls, xpriv, index: int):
        '''
        Derive a BIP32 extended key.
        '''
        entropy = cls.entropy(xpriv, "m/83696968'/32'/{}'".format(index))
        assert len(entropy)==64
        key = ExtendedKey(PrivKey(big_endian_to_int(entropy[32:])), entropy[:32])
        return key

    @classmethod
    def app_hex(cls, xpriv, num_bytes:int, index:int):
        '''
        Generate less than 64 random bytes.
        '''
        assert num_bytes>=16 and num_bytes<=64
        entropy = cls.entropy(xpriv,"m/83696968'/128169'/{}'/{}'".format(num_bytes,index))
        assert len(entropy)==64
        return entropy[:num_bytes]


    @classmethod
    def app_pwd64(cls, xpriv, pwd_len: int, index: int):
        '''
        Password generator in base 64.
        '''
        # TODO: test
        assert pwd_len>=20 and pwd_len<=86
        entropy = cls.entropy(xpriv,"m/83696968'/707764'/{}'/{}'".format(pwd_len,index))
        pwd = base64.b64encode(entropy).decode('ascii').strip('=')
        return pwd[:pwd_len]

    @classmethod
    def app_pwd85(cls, xpriv, pwd_len: int, index: int):
        '''
        Password generator in base 85.
        '''
        # TODO: test
        assert pwd_len>=10 and pwd_len<=80
        entropy = cls.entropy(xpriv,"m/83696968'/707785'/{}'/{}'".format(pwd_len,index))
        pwd = base64.b85encode(entropy).decode('ascii').strip('=')
        return pwd[:pwd_len]


    @classmethod
    def app_rsa(cls, xpriv, key_bits: int, index: int):
        '''
        Generate a set of RSA keys.
        '''
        # TODO: test
        def rsa_from_xpriv(m):
            drng = bip85_drng(bip85_entropy(m,'m'))
            return RSA.generate(bits=key_bits, randfunc=m.read,e=65537)


        certify = xpriv.derivation_path("m/83696968'/828365'/{}'/{}'".format(key_bits,index))
        certify_rsa = rsa_from_xpriv(certify)

        encryption = certify.derivation_path("m/0'")
        encryption_rsa = rsa_from_xpriv(encryption)

        authentication = certify.derivation_path("m/1'")
        authentication_rsa = rsa_from_xpriv(authentication)

        signature = certify.derivation_path("m/2'")
        signature_rsa = rsa_from_xpriv(signature)

        return certify_rsa, encryption_rsa, authentication_rsa, signature_rsa
