#!/usr/bin/env python
from hackbitcoin.bip39 import Mnemonic
from hackbitcoin.extkey import ExtendedKey
from hackbitcoin.bip85 import BIP85


if __name__=="__main__":

    mnemonic = input("Enter the parent mnemonic: ")
    print()

    passphrase = input("Passphrase (can be empty): ")
    print('Passphrase is:"{}"'.format(passphrase))

    xpriv = Mnemonic.master_key(mnemonic.strip(), passphrase)

    print()

    nwords = input("Length of child mnemonic sentence (12 or 24): ")
    if not( nwords=='12' or nwords=='24'):
        raise ValueError('you must enter either 12 or 24')
    nwords = int(nwords)

    print()

    index = input("Index of child mnemonic sentence (0 to 2147483647): ")

    print()

    result = BIP85.app_mnemonic(xpriv, nwords, index)
    print("Child mnemonic is:", result)
