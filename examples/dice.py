#!/usr/bin/env python
from hackbitcoin.bip39 import Mnemonic
from hackbitcoin.hash import sha256
from hackbitcoin.extkey import ExtendedKey

import sys
import math
import qrcode


def only_these_chars(string, alphabet):
    new_str = ''
    for c in string:
        if c in alphabet:
            new_str += c
    return new_str


def min_events(bits):
    single_dice = math.log2(6)
    return math.ceil(bits/single_dice)


def entropy_bits(nwords):
    message_bits = nwords * 11
    assert message_bits % 33 == 0
    CS = message_bits // 33
    ENT = message_bits - CS
    return ENT


def main(dice_roll: str, nwords: int=12, passphrase: str=''):
    '''
    '''
    entropy_bytes = entropy_bits(nwords)//8
    entropy = sha256(dice_roll.encode())[:entropy_bytes]
    mnemonic = Mnemonic.generate(entropy)

    assert len(mnemonic.split()) == nwords

    print('Mnemonic phrase:', mnemonic)

    masterkey = Mnemonic.master_key(mnemonic, passphrase)
    print("BIP32 root key:", masterkey.export_format())
    print("fingerprint:", masterkey.fingerprint().hex())
    print('\n')

    def show_keys(xpriv):
        xpubk = xpriv.neutered()
        xpriv_fmt = xpriv.export_format()
        xpubk_fmt = xpubk.export_format()
        print("xpriv:", xpriv_fmt)
        print("xpubk:", xpubk_fmt)
        print('\n')
        img = qrcode.make(xpubk_fmt).get_image()
        img.show()
        input('continue...')
        # TODO: show first 3 addresses

    print("Legacy wallet (m/44'/0'/0')")
    xpriv = masterkey.derivation_path("m/44'/0'/0'")
    xpriv.set_version(scheme = 'P2PKH')
    show_keys(xpriv)

    print("Wrapped segwit (m/49'/0'/0')")
    xpriv = masterkey.derivation_path("m/49'/0'/0'")
    xpriv.set_version(scheme = 'P2SH(P2WPKH)')
    show_keys(xpriv)

    print("Native segwit (m/84'/0'/0')")
    xpriv = masterkey.derivation_path("m/84'/0'/0'")
    xpriv.set_version(scheme = 'P2WPKH')
    show_keys(xpriv)

def test():
    assert entropy_bits(12)==128
    assert entropy_bits(24)==256
    assert min_events(128)==50
    assert min_events(256)==100


if __name__=="__main__":
    test()

    dice_roll = input("Enter the dice sequence [1,6]: ")
    s = only_these_chars(dice_roll, {'1','2','3','4','5','6'})
    if s!=dice_roll:
        dice_roll = s
        print('WARNING: some characters have been removed from your input.')
    print('Entropy will be computed with the following string:',dice_roll)

    print()

    nwords = input("Length of mnemonic sentence (12 or 24): ")
    if not( nwords=='12' or nwords=='24'):
        raise ValueError('you must enter either 12 or 24')
    nwords = int(nwords)
    bits = entropy_bits(nwords)
    need_events = min_events(bits)
    nevents = len(dice_roll)

    if nevents < need_events:
        print("WARNING: for {} words ({} bits of entropy) we need at least {} "
        "dice roll events, {} were given.".format(nwords, bits, need_events,
        nevents))


    print()

    passphrase = input("Passphrase (can be empty): ")
    print('Passphrase is:"{}"'.format(passphrase))

    print()

    main(dice_roll, nwords, passphrase)
