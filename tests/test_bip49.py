from .context import hackbitcoin

# Checks against bip32.org

import pytest
from hackbitcoin.ecc import PubKey, PrivKey
from hackbitcoin.extkey import ExtendedKey
from hackbitcoin.address import Address
from hackbitcoin.bip39 import Mnemonic, mybip39
from hackbitcoin.hash import hash160
from hackbitcoin.script import Script
from hackbitcoin.base58 import base58
from hackbitcoin.network import Network

def test_1():
    masterseedWords = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    masterseed = Mnemonic.master_key(masterseedWords, '')
    masterseed.set_version(network='testnet', scheme='P2SH(P2WPKH)')

    assert masterseed.export_format()=='uprv8tXDerPXZ1QsVNjUJWTurs9kA1KGfKUAts74GCkcXtU8GwnH33GDRbNJpEqTvipfCyycARtQJhmdfWf8oKt41X9LL1zeD2pLsWmxEk3VAwd'

    # account 0
    derived = masterseed.derivation_path("m/49'/1'/0'")
    assert derived.export_format()=='uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n'
    assert derived.neutered().export_format()=='upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY'

    # account 0, first key
    derived = masterseed.derivation_path("m/49'/1'/0'/0/0")
    key = derived.key
    assert key.export_format(network='testnet')=='cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ'
    assert key.serialize().hex() == 'c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8'
    assert key.PubKey().serialize().hex()=='03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f'

    # address derivation
    pubkey = key.PubKey()
    pk_hash = hash160(pubkey.serialize())
    assert pk_hash.hex() == '38971f73930f6c141d977ac4fd4a727c854935b3'
    scriptSig = Script.from_opcodes([\
        Script.OP_0, pk_hash]).serialize()[1:]
    assert scriptSig.hex() =='001438971f73930f6c141d977ac4fd4a727c854935b3'
    addressBytes = hash160(scriptSig)
    assert addressBytes.hex() =='336caa13e08b96080a32b5d818d59b4ab3b36742'
    prefix = Network.address_prefix('P2SH', 'testnet')
    address = base58.encode_checksum(prefix+addressBytes)
    assert address=='2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2'
    assert Address.address(pubkey, scheme='P2SH(P2WPKH)',network='testnet')==address
