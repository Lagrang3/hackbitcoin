#!/usr/bin/env python
from hackbitcoin.bip39 import Mnemonic
from hackbitcoin.extkey import ExtendedKey
from hackbitcoin.address import Address


if __name__=="__main__":

    mnemonic = input("Enter mnemonic: ")
    print()

    passphrase = input("Passphrase (can be empty): ")
    print('Passphrase is:"{}"'.format(passphrase))

    masterkey = Mnemonic.master_key(mnemonic.strip(), passphrase)

    def show_keys(xpriv, scheme):
        xpubk = xpriv.neutered()
        xpriv_fmt = xpriv.export_format()
        xpubk_fmt = xpubk.export_format()
        print("xpriv:", xpriv_fmt)
        print("xpubk:", xpubk_fmt)
        print('\n')
        #input('continue...')
        path = 'm'
        xderived = xpubk.derivation_path(path)

        # Now let's check the receiving addresses
        print('Receiving addresses')
        for i in range(10):
            path = 'm/0/{}'.format(i)
            xkey = xderived.derivation_path(path)
            print(path, Address.address(xkey.key,
                scheme=scheme,
                network=xkey.network()))

        print()

        print('Change addresses')
        for i in range(10):
            path = 'm/1/{}'.format(i)
            xkey = xderived.derivation_path(path)
            print(path, Address.address(xkey.key,
                scheme=scheme,
                network=xkey.network()))

        print()

    print("Legacy wallet (m/44'/0'/0')")
    xpriv = masterkey.derivation_path("m/44'/0'/0'")
    xpriv.set_version(scheme = 'P2PKH')
    show_keys(xpriv, scheme='P2PKH')

    print("Wrapped segwit (m/49'/0'/0')")
    xpriv = masterkey.derivation_path("m/49'/0'/0'")
    xpriv.set_version(scheme = 'P2SH(P2WPKH)')
    show_keys(xpriv, scheme='P2SH(P2WPKH)')

    print("Native segwit (m/84'/0'/0')")
    xpriv = masterkey.derivation_path("m/84'/0'/0'")
    xpriv.set_version(scheme = 'P2WPKH')
    show_keys(xpriv, scheme='P2WPKH')
