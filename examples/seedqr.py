#!/usr/bin/env python
import io
import sys
import qrcode
from hackbitcoin.bip39 import Mnemonic

def show_help():
    print("Usage: seedqr.py <mnemonic>")
    sys.exit(1)

def check_mnemonic(mnemonic):
    return Mnemonic.is_valid(mnemonic)

def print_qrcode(data):
    qr = qrcode.QRCode()
    qr.add_data(data)
    qr.print_ascii(out=sys.stdout, tty=True)

if __name__=="__main__":

    if len(sys.argv) != 2:
        show_help()

    mnemonic = sys.argv[1]
    if not check_mnemonic(mnemonic):
        show_help()

    decode = Mnemonic.decode(mnemonic)
    print_qrcode(decode)
