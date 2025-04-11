# Example program used to derive the descriptor for core-lightning's wallet
# input: the xpub returned by hsmtool
# output: the xpub from which addresses are generated, eg. this xpub can be
# placed into a sparrow wallet and it will generate all the node's wallet
# addresses.
from hackbitcoin.extkey import ExtendedKey

x = input('give me your xpub: ')

k = ExtendedKey.import_format(x)
k.set_version(scheme='P2WPKH')
k0 = k.derivation_path('m/0')
print(k0.export_format())
