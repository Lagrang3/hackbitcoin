# All kind of hashing functions

# TODO: write my own sha256, ripemd160 and HMAC
import Crypto.Hash.SHA256
import Crypto.Hash.SHA512
import Crypto.Hash.RIPEMD160
import Crypto.Hash.HMAC
from Crypto.Protocol.KDF import PBKDF2


def hash160(message):
    """SHA256 followed by RIPEMD160"""
    h256 = Crypto.Hash.SHA256.new()
    h160 = Crypto.Hash.RIPEMD160.new()
    h256.update(message)
    h160.update(h256.digest())
    return h160.digest()


def double_sha256(message):
    h = Crypto.Hash.SHA256.new()
    h2 = Crypto.Hash.SHA256.new()
    h.update(message)
    h2.update(h.digest())
    return h2.digest()


def sha256(message):
    h = Crypto.Hash.SHA256.new()
    h.update(message)
    return h.digest()


def hmac_sha256(secret, message):
    h = Crypto.Hash.HMAC.new(secret,digestmod=Crypto.Hash.SHA256)
    h.update(message)
    return h.digest()


def hmac_sha512(secret, message):
    h = Crypto.Hash.HMAC.new(secret,digestmod=Crypto.Hash.SHA512)
    h.update(message)
    return h.digest()


def pbkdf2_hmac_sha512(password, salt, iterations):
    return PBKDF2(password, salt, 64, count = iterations, \
        hmac_hash_module=Crypto.Hash.SHA512)
