#!/usr/bin/env python
'''
    This is a script I wrote because I wanted to track on-chain funds from
    core-lightning into another wallet.
'''


from hackbitcoin.bip39 import Mnemonic
from hackbitcoin.extkey import ExtendedKey
from hackbitcoin.address import Address

if __name__=="__main__":

    # First give the xpub
    xpub_str = input('xpub: ')
    xpub = ExtendedKey.import_format(xpub_str)

    print()

    # The full derivation path is m/0/0/*, but since Sparrow wallet only accepts
    # m/<0,1>/* in the descriptor we need to go one level deper.
    path = 'm/0'

    print()

    xderived = xpub.derivation_path(path)

    # This derived xpub can be already used into Sparrow
    print(xderived.export_format())

    xderived.set_version(scheme='P2WPKH')

    # Now let's check the receiving addresses
    print('Receiving addresses')
    for i in range(10):
        path = 'm/0/{}'.format(i)
        xkey = xderived.derivation_path(path)
        print(path, Address.p2wpkh(xkey.key, network=xkey.network()))

    print()

    print('Change addresses')
    for i in range(10):
        path = 'm/1/{}'.format(i)
        xkey = xderived.derivation_path(path)
        print(path, Address.p2wpkh(xkey.key, network=xkey.network()))
