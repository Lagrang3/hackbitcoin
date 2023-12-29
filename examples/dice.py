from hackbitcoin.bip39 import Mnemonic
from hackbitcoin.hash import sha256
from hackbitcoin.extkey import ExtendedKey

dice_roll = 10*'1' + 10*'2' + 10*'3' + 10*'4' + 10*'5'
entropy = sha256(dice_roll.encode())
mnemonic = Mnemonic.generate(entropy[:16])
print(mnemonic)
xpriv = Mnemonic.master_key(mnemonic)
xpub = xpriv.neutered()
print(xpriv)
print(xpriv.fingerprint().hex())

#xpriv_derived = xpriv.CDK(84, hardened=True).CDK(0, hardened=True).CDK(0,hardened=True)
xpriv_derived = xpriv.derivation_path("m/84'/0'/0'")
xpub_derived = xpriv_derived.neutered()
print(xpub_derived)

# TODO: consider segwit wallets
