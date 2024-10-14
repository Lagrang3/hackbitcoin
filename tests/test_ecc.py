from .context import hackbitcoin

import pytest
from hackbitcoin.ecc import PubKey, PrivKey, Signature, ecdsa
from hackbitcoin.secp256k1 import secp256k1_Point
from hackbitcoin.hash import double_sha256
from hackbitcoin.address import Address

def test_PubKey_serialization():
    p = PubKey.from_PrivKey(PrivKey(2018**5, compressed=False))
    ser = '04027f3da1918455e03c46f659266a1bb5204e959db7364d2f473bdf8f0a13cc9dff87647fd023c13b4a4994f17691895806e1b40b57f4fd22581a4f46851f3b06'
    assert p.serialize().hex() == ser
    assert p == PubKey.parse(bytes.fromhex(ser))

    p = PrivKey(0xdeadbeef12345,compressed=False).PubKey()
    ser = '04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121'
    assert p.serialize().hex() == ser
    assert p == PubKey.parse(bytes.fromhex(ser))

    p = PrivKey(5001).PubKey()
    ser ='0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1'
    assert p.serialize().hex() == ser
    assert p == PubKey.parse(bytes.fromhex(ser))

    p = PrivKey(2019**5).PubKey()
    ser = '02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701'
    assert p.serialize().hex() == ser
    assert p == PubKey.parse(bytes.fromhex(ser))

    p = PrivKey(0xdeadbeef54321).PubKey()
    ser = '0296be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690'
    assert p.serialize().hex() == ser
    assert p == PubKey.parse(bytes.fromhex(ser))


def test_PrivKey_serialization():
    p = PrivKey(5003)
    wif = 'cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK'
    assert wif == p.wif(network='testnet')
    key, net = PrivKey.from_wif(wif)
    assert key == p
    assert net == 'testnet'

    p = PrivKey(2021**5,compressed=False)
    wif = '91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjpWAxgzczjbCwxic'
    assert wif == p.wif(network='testnet')
    key, _ = PrivKey.from_wif(wif)
    assert key == p
    assert net == 'testnet'

    p = PrivKey(0x54321deadbeef)
    wif = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgiuQJv1h8Ytr2S53a'
    assert wif == p.wif(network='mainnet')
    key, net = PrivKey.from_wif(wif)
    assert key == p
    assert net == 'mainnet'


def test_address():
    p = PubKey.from_PrivKey(PrivKey(5002,compressed=False))
    assert Address.p2pkh(p,network='testnet') == 'mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA'

    p = PubKey.from_PrivKey(PrivKey(2020**5))
    assert Address.p2pkh(p,network='testnet') == 'mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH'

    p = PubKey.from_PrivKey(PrivKey(0x12345deadbeef))
    assert Address.p2pkh(p,network='mainnet') == '1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1'

    assert Address.address(p, scheme='P2SH(P2PKH)',network='mainnet') == '38A88P5BTTo3AfWtCgFnrMfcqgPbE5NuE8'
    assert Address.address(p, scheme='P2SH(P2WPKH)',network='mainnet') == '37XT8e1HMLe9YQ2ufRjvrG6BJVPrENo9Ux'

    p = PubKey.parse( \
            bytes.fromhex( \
                '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'))
    assert Address.p2wpkh(p) == 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'

    p = PubKey.parse( \
            bytes.fromhex( \
                '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'))
    assert Address.p2wpkh(p) == 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
    assert Address.p2wpkh(p,network='testnet') == 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'


def test_Signature_serialization():
    r = 0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6
    s = 0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec
    sig = Signature(r,s)
    sig_der = '3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec'
    assert sig_der==sig.serialize().hex()
    assert Signature.parse(bytes.fromhex(sig_der))==sig


def test_ecdsa():
    px=0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574
    py=0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4
    point = secp256k1_Point(px,py)
    pub = PubKey(point)

    m=0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423
    Rx=0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6
    s=0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec
    sig = Signature(Rx,s)
    assert ecdsa.verify_signature(pub,m,sig)

    px=0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c
    py=0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34
    point = secp256k1_Point(px,py)
    pub = PubKey(point)

    m=0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60
    Rx=0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395
    s=0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4
    sig = Signature(Rx,s)
    assert ecdsa.verify_signature(pub,m,sig)

    m=0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
    Rx=0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c
    s=0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6
    sig = Signature(Rx,s)
    assert ecdsa.verify_signature(pub,m,sig)

    z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
    sec = bytes.fromhex('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')
    sig = bytes.fromhex('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6')
    p = PubKey.parse(sec)
    s = Signature.parse(sig)
    assert ecdsa.verify_signature(p,z,s)

    N = secp256k1_Point.N

    e = PrivKey(12345)
    pub = PubKey.from_PrivKey(e)
    m = int.from_bytes(double_sha256('Programming Bitcoin!'.encode()),'big')
    sig = ecdsa.sign(e,m)
    assert ecdsa.verify_signature(pub,m,sig)

    # also -s is valid
    sig.s = N -sig.s
    assert ecdsa.verify_signature(pub,m,sig)

    m = int.from_bytes(double_sha256('another message'.encode()),'big')
    sig = ecdsa.sign(e,m)
    assert ecdsa.verify_signature(pub,m,sig)

    # also -s is valid
    sig.s = N -sig.s
    assert ecdsa.verify_signature(pub,m,sig)

    sighash = '27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6'
    signature = '3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed'
    pubk_hex = '0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a'

    pk = PubKey.parse(bytes.fromhex(pubk_hex))
    m = int.from_bytes(bytes.fromhex(sighash), 'big')
    sig = Signature.parse(bytes.fromhex(signature))
    assert ecdsa.verify_signature(pk, m, sig)

    sighash = 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670'
    signature = '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee'
    pubk_hex = '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357'

    pk = PubKey.parse(bytes.fromhex(pubk_hex))
    m = int.from_bytes(bytes.fromhex(sighash), 'big')
    sig = Signature.parse(bytes.fromhex(signature))
    assert ecdsa.verify_signature(pk, m, sig)
