from hackbitcoin.bip39 import Mnemonic
from hackbitcoin.hash import sha256
from hackbitcoin.extkey import ExtendedKey

dice_roll = 10*'1' + 10*'2' + 10*'3' + 10*'4' + 10*'5'
entropy = sha256(dice_roll.encode())

mnemonic = Mnemonic.generate(entropy[:16])
assert mnemonic == 'limit palace swing matter antique come sea canvas cigar decide damage sea'
print("mnemonic:", mnemonic)

xpriv = Mnemonic.master_key(mnemonic)

xpriv_str = str(xpriv)
assert xpriv_str=='xprv9s21ZrQH143K466vGp3fvz8f57ZVX52WQuGMXG48XpcYAx3Yu12aYZg59nZRuuAskKNKj3dUxhdokYtDPVdgmLg76gQiFJV62r9y8Rp3vs5'
print("BIP32 root key:", xpriv_str)

fingerprint = xpriv.fingerprint().hex()
assert fingerprint == '084f6082'
print("root key fingerpring:", fingerprint)

xpriv_derived = xpriv.derivation_path("m/49'/0'/0'")
xpriv_derived.set_version(scheme='P2SH(P2WPKH)')

xpub_derived = xpriv_derived.neutered()
print(xpub_derived.export_format())
