from .context import hackbitcoin

import pytest
from hackbitcoin.base58 import base58

def test_base58():
    binary_mes = b'hello world'
    base58_mes = 'StV1DL6CwTryKyV'
    assert base58_mes == base58.encode(binary_mes)
    assert base58.decode(base58_mes) == binary_mes
