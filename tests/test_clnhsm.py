from .context import hackbitcoin

# Checks against core-lightning

import pytest
from hackbitcoin.extkey import ExtendedKey
from hackbitcoin.address import Address
from hackbitcoin.cln_tools import HSM

def test_hsm_secret():
    mnemonic = 'ivory spatial income exhibit outer canoe better essay trophy lumber order mistake'
    passphrase = 'testing cln'

    hsm_secret = HSM.generate_hsm(mnemonic, passphrase)
    assert hsm_secret.hex()=='15f3de6ab9a12c4431a9fb02c9129df108e6a1ab73b22789fc0553e904d669d5'

def test_extended_key():
    mnemonic = 'ivory spatial income exhibit outer canoe better essay trophy lumber order mistake'
    passphrase = 'testing cln'

    xkey = HSM.generateExtendedKey(mnemonic, passphrase)
    xpub = xkey.neutered()
    assert xpub.export_format()=='xpub661MyMwAqRbcFk7TVuPRm4iAR5syTM3cQFfZoRei7bPw69BgXC7qzxAyoTx6k5KcxG4XY5DAsmb8i2TEDzbNFiyz8SPeHHogswr7W2nXrLt'
