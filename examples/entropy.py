#!/usr/bin/env python
import sys
from hackbitcoin.bip39 import Mnemonic
from hackbitcoin.extkey import ExtendedKey
from hackbitcoin.bip85 import BIP85

"""
Generatee deterministic entropy
"""

def show_help():
    print("Usage: entropy.py <mnemonic> <passphrase> <byte length> <index of child (0 to 2147483647)>")
    sys.exit(1)

def check_length(n):
    try:
        i = int(n)
        if i<16 or i>64:
            return False
    except:
        return False
    return True

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

    length = sys.argv[3]
    if not check_length(length):
        show_help()
    length = int(length)

    index = sys.argv[4]
    if not check_index(index):
        show_help()
    index = int(index)

    result = BIP85.app_hex(xpriv, length, index).hex()
    print(result)
