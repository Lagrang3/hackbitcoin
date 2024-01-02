#!/usr/bin/env python
from hackbitcoin.bip39 import Mnemonic
from hackbitcoin.hash import sha256
from hackbitcoin.extkey import ExtendedKey

import sys

def main(dice_roll: str, nwords: int=12, passphrase: str=''):
    '''
    '''
    entropy_bytes = 16 if nwords==12 else 32
    entropy = sha256(dice_roll.encode())[:entropy_bytes]
    mnemonic = Mnemonic.generate(entropy)

    assert len(mnemonic.split()) == nwords

    print('Mnemonic phrase:', mnemonic)

    masterkey = Mnemonic.master_key(mnemonic, passphrase)
    print("BIP32 root key:", masterkey.export_format())
    print("fingerprint:", masterkey.fingerprint().hex())
    print('\n')

    xpriv = masterkey.derivation_path("m/44'/0'/0'")
    xpriv.set_version(scheme = 'P2PKH')
    print("Legacy wallet (m/44'/0'/0')")
    print("xpriv:", xpriv.export_format())
    print("xpubk:", xpriv.neutered().export_format())
    print('\n')


    xpriv = masterkey.derivation_path("m/49'/0'/0'")
    xpriv.set_version(scheme = 'P2SH(P2WPKH)')
    print("Wrapped segwit (m/49'/0'/0')")
    print("xpriv:", xpriv.export_format())
    print("xpubk:", xpriv.neutered().export_format())
    print('\n')

    xpriv = masterkey.derivation_path("m/84'/0'/0'")
    xpriv.set_version(scheme = 'P2WPKH')
    print("Native segwit (m/84'/0'/0')")
    print("xpriv:", xpriv.export_format())
    print("xpubk:", xpriv.neutered().export_format())
    print('\n')


if __name__=="__main__":
    assert len(sys.argv)>=3

    dice_roll = sys.argv[1]
    nwords = sys.argv[2]

    assert nwords=='12' or nwords=='24'

    passphrase = ''
    if len(sys.argv)>3:
        passphrase = sys.argv[3]

    main(dice_roll, int(nwords), passphrase)
