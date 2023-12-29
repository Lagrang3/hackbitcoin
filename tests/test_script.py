import pytest
from io import BytesIO

from .context import hackbitcoin
from hackbitcoin.script import Script
from hackbitcoin.hash import hash160

def test_script_empty():
    empty = b'\x00'
    s = Script.parse(BytesIO(empty))
    assert empty == s.serialize()

def test_script_decode():
    s = Script.from_opcodes([Script.OP_DUP, Script.OP_HASH160, \
            bytes.fromhex('dc751feb90ab97f90ac87d099005957852305ba3'),
            Script.OP_EQUALVERIFY, Script.OP_CHECKSIG])
    assert s.serialize().hex() == '1976a914dc751feb90ab97f90ac87d099005957852305ba388ac'

def test_p2pk():
    z = bytes.fromhex('7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d')
    pubkey = bytes.fromhex('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')
    signature = bytes.fromhex('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601')

    scriptpubkey = Script.from_opcodes([pubkey, Script.OP_CHECKSIG])
    scriptsig = Script.from_opcodes([signature])

    combined = scriptsig + scriptpubkey
    def sighash_getter(sighash_flag):
        return z
    assert combined.evaluate(sighash_getter)

def test_p2pkh():
    z = bytes.fromhex('7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d')
    pubkey = bytes.fromhex('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')
    signature = bytes.fromhex('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601')

    pubkeyhash = hash160(pubkey)

    scriptpubkey = Script.from_opcodes([Script.OP_DUP, Script.OP_HASH160,
        pubkeyhash, Script.OP_EQUALVERIFY, Script.OP_CHECKSIG])
    scriptsig = Script.from_opcodes([signature, pubkey])

    combined = scriptsig + scriptpubkey
    def sighash_getter(sighash_flag):
        return z
    assert combined.evaluate(sighash_getter)
