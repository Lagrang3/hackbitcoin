#!/usr/bin/env python
from hackbitcoin.cln_tools import HSM

if __name__=="__main__":

    mnemonic = input("Enter the mnemonic sentence: ")
    print()

    passphrase = input("Enter the passphrase (can be empty): ")
    print("Passphrase is: \"{}\"".format(passphrase))
    print()

    hsm = HSM.generate_hsm(mnemonic, passphrase)
    print(hsm.hex())
