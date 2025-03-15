#!/usr/bin/env python
import sys
from hackbitcoin.bip39 import Mnemonic
from hackbitcoin.extkey import ExtendedKey
from hackbitcoin.bip85 import BIP85

def show_help():
    print("Usage: child.py <mnemonic> <passphrase> <length of child (12 or 24)> <index of child (0 to 2147483647)>")
    sys.exit(1)

def check_nwords(nwords):
    return nwords=='12' or nwords=='24'

def check_index(index):
    try:
        i = int(index)
        if i<0 or i>2147483647:
            return False
    except:
        return False
    return True

def check_passphrase(passphrase):
    return True

def check_mnemonic(mnemonic):
    return Mnemonic.is_valid(mnemonic)

if __name__=="__main__":

    if len(sys.argv) != 5:
        show_help()

    mnemonic = sys.argv[1]
    if not check_mnemonic(mnemonic):
        show_help()

    passphrase = sys.argv[2]
    if not check_passphrase(passphrase):
        show_help()

    xpriv = Mnemonic.master_key(mnemonic.strip(), passphrase)

    nwords = sys.argv[3]
    if not check_nwords(nwords):
        show_help()
    nwords = int(nwords)

    index = sys.argv[4]
    if not check_index(index):
        show_help()
    index = int(index)

    result = BIP85.app_mnemonic(xpriv, nwords, index)
    print(result)
