from .context import hackbitcoin

import pytest
from hackbitcoin.hash import hash160, sha256, double_sha256

def test_sha256():
    assert sha256(b'').hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256('hello'.encode()).hex() == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_double_sha256():
    assert double_sha256(b'').hex() == "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
    assert double_sha256('hello'.encode()).hex() == "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"

def test_hash160():
    assert hash160(b'').hex() == "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
    assert hash160('hello'.encode()).hex() == "b6a9c8c230722b7c748331a8b450f05566dc7d0f"
