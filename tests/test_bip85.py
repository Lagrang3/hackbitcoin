from .context import hackbitcoin

import pytest
from hackbitcoin.bip85 import BIP85, DRNG
from hackbitcoin.extkey import ExtendedKey

def test_entropy():
    m = ExtendedKey.import_format('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb')
    entropy = BIP85.entropy(m, "m/83696968'/0'/0'")
    assert entropy.hex()=='efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7'

    generator = DRNG(entropy)
    data = generator.read(80)
    assert data.hex()=='b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd883d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc8c7355b87a925a37ee405a7502991111'

    m = ExtendedKey.import_format('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb')
    entropy = BIP85.entropy(m, "m/83696968'/0'/1'")
    assert entropy.hex()=='70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e'


def test_bip39():
    testvector = [\
        ('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb',
            12, 0,
            'girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose'),
        ('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb',
            18, 0,
            'near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token'),
        ('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb',
            24, 0,
            'puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano'),
        ]
    for x, nwords, index, expected_mnemonic in testvector:
        m = ExtendedKey.import_format(x)
        mnemonic = BIP85.app_mnemonic(m, nwords, index)
        assert mnemonic == expected_mnemonic

def test_hdseed():
    m = ExtendedKey.import_format('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb')
    k = BIP85.app_hdseed(m,0)
    assert k.export_format()=='Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp'

def test_xpriv():
    m = ExtendedKey.import_format('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb')
    k = BIP85.app_xpriv(m,0)
    assert k.export_format()=='xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX'

def test_hex():
    m = ExtendedKey.import_format('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb')
    h = BIP85.app_hex(m,64,0)
    assert h.hex()=='492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c'

def test_pwd64():
    m = ExtendedKey.import_format('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb')
    pwd = BIP85.app_pwd64(m,21,0)
    assert pwd=='dKLoepugzdVJvdL56ogNV'

def test_pwd85():
    m = ExtendedKey.import_format('xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb')
    pwd = BIP85.app_pwd85(m,12,0)
    assert pwd=='_s`{TW89)i4`'
