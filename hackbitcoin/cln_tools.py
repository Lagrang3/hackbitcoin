# From the source code of core-lightning, see https://github.com/ElementsProject/lightning/blob/master/tools/hsmtool.c

from .hash import hkdf_sha256
from .bip39 import mybip39
from .extkey import ExtendedKey

class HSM:

    @classmethod
    def generate_hsm(cls, mnemonic, passphrase=""):
        """
        Generates the 32 byte hsm_secret from a mnemonic sentence.

        This procedure is similar to the way a seed is generated from a mnemonic
        sentence according to BIP39. The only difference is the truncation of
        the data from 64 to 32 bytes, otherwise the hsm_secret of core-lightning
        would have been equal to the seed generated by BIP39 specification.
        """
        assert mybip39._validate(mnemonic)
        return mybip39._seed_from_mnemonic(mnemonic, passphrase)[:32]

    @classmethod
    def _secret_to_seed(cls, secret, salt: int=0):
        """
        Takes a hsm_secret and produces the seed from which a BIP32 HDwallet is
        generated.

        Note: it is evident that the hsm_secret is NOT the BIP32 seed.
        """
        return hkdf_sha256(secret, salt.to_bytes(4, 'little'), 'bip32 seed'.encode())

    @classmethod
    def _seed_to_ExtendedKey(cls, seed):
        """
        From the seed computes an extended key. The procedure is the same
        specified in BIP32.
        """
        return ExtendedKey.from_seed(seed, network='mainnet', scheme='P2PKH')

    @classmethod
    def generateExtendedKey(cls, mnemonic, passphrase = ""):
        """
        Generates the extended private keys used by core-lightning starting from
        a mnemonic sentence.
        """
        secret = cls.generate_hsm(mnemonic, passphrase)
        seed = cls._secret_to_seed(secret)
        return cls._seed_to_ExtendedKey(seed)
