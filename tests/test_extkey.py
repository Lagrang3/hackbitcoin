from .context import hackbitcoin

# Checks against bip32.org

import pytest
from hackbitcoin.ecc import PubKey, PrivKey
from hackbitcoin.extkey import ExtendedKey
from hackbitcoin.address import Address
from hackbitcoin.bip39 import Mnemonic
from hackbitcoin.hash import hash160, sha256


def check_serialization(x):
    s = str(x)
    x2 = ExtendedKey.import_format(s)
    assert x.key == x2.key
    assert x == x2
    assert str(x) == str(x2)

def get_address(xpub):
    return Address.p2pkh(xpub.key, network = xpub.network())

def get_wif(xpriv):
    return xpriv.key.wif(network = xpriv.network())


def test_1():

    seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    m = ExtendedKey.from_seed(seed)
    check_serialization(m)
    M = m.neutered()
    check_serialization(M)

    assert str(m) == 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
    assert get_wif(m) == 'L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW'

    assert str(M) == 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
    assert get_address(M) == '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma'

    m_0h = m.CDK(0, hardened=True)
    check_serialization(m_0h)
    m_0hN = m_0h.neutered()
    check_serialization(m_0hN)

    assert str(m_0h) == 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'
    assert get_wif(m_0h) == 'L5BmPijJjrKbiUfG4zbiFKNqkvuJ8usooJmzuD7Z8dkRoTThYnAT'

    assert str(m_0hN) == 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'
    assert get_address(m_0hN) == '19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh'

    m_0h_1 = m_0h.CDK(1, hardened=False)
    check_serialization(m_0h_1)

    m_0h_1N = m_0h_1.neutered()
    check_serialization(m_0h_1N)

    assert str(m_0h_1) == 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'
    assert get_wif(m_0h_1) == 'KyFAjQ5rgrKvhXvNMtFB5PCSKUYD1yyPEe3xr3T34TZSUHycXtMM'

    assert str(m_0h_1N) == 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'
    assert get_address(m_0h_1N) == '1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj'

    m_0hN_1 = m_0hN.CDK(1)
    check_serialization(m_0hN_1)

    assert str(m_0hN_1) == 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'
    assert get_address(m_0hN_1) == '1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj'

    m_0h_1_2h = m_0h_1.CDK(2, hardened=True)
    m_0h_1_2hN = m_0h_1_2h.neutered()
    check_serialization(m_0h_1_2h)
    check_serialization(m_0h_1_2hN)

    assert str(m_0h_1_2h) == 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'
    assert get_wif(m_0h_1_2h) == 'L43t3od1Gh7Lj55Bzjj1xDAgJDcL7YFo2nEcNaMGiyRZS1CidBVU'

    assert str(m_0h_1_2hN) == 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5'
    assert get_address(m_0h_1_2hN) == '1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x'

    m_0h_1_2h_2 = m_0h_1_2h.CDK(2, hardened=False)
    check_serialization(m_0h_1_2h_2)

    assert str(m_0h_1_2h_2) == 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'
    assert get_wif(m_0h_1_2h_2) == 'KwjQsVuMjbCP2Zmr3VaFaStav7NvevwjvvkqrWd5Qmh1XVnCteBR'

    assert str(m_0h_1_2h_2.neutered()) == 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV'
    assert get_address(m_0h_1_2h_2.neutered()) == '1LjmJcdPnDHhNTUgrWyhLGnRDKxQjoxAgt'

    m_0h_1_2hN_2 = m_0h_1_2hN.CDK(2)
    check_serialization(m_0h_1_2hN_2)

    assert str(m_0h_1_2hN_2) == 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV'
    assert get_address(m_0h_1_2hN_2) == '1LjmJcdPnDHhNTUgrWyhLGnRDKxQjoxAgt'

    m_0h_1_2h_2_1000000000 = m_0h_1_2h_2.CDK(1000000000, hardened=False)
    check_serialization(m_0h_1_2h_2_1000000000)

    assert str(m_0h_1_2h_2_1000000000) == 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'
    assert get_wif(m_0h_1_2h_2_1000000000) == 'Kybw8izYevo5xMh1TK7aUr7jHFCxXS1zv8p3oqFz3o2zFbhRXHYs'

    assert str(m_0h_1_2h_2_1000000000.neutered()) == 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy'
    assert get_address(m_0h_1_2h_2_1000000000.neutered()) == '1LZiqrop2HGR4qrH1ULZPyBpU6AUP49Uam'

    m_0h_1_2hN_2_1000000000 = m_0h_1_2hN_2.CDK(1000000000)
    check_serialization(m_0h_1_2hN_2_1000000000)

    assert str(m_0h_1_2hN_2_1000000000) == 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy'
    assert get_address(m_0h_1_2hN_2_1000000000) == '1LZiqrop2HGR4qrH1ULZPyBpU6AUP49Uam'


def test_2():
    seed = bytes.fromhex('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542 ')

    m = ExtendedKey.from_seed(seed)
    M = m.neutered()
    check_serialization(m)
    check_serialization(M)

    assert str(m) == 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U'
    assert str(M) == 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'

    m_0 = m.CDK(0)
    M_0 = M.CDK(0)
    m_0N = m_0.neutered()
    check_serialization(m_0)
    check_serialization(M_0)
    check_serialization(m_0N)

    assert str(m_0) == 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'
    assert str(M_0) == 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'
    assert str(m_0N) == 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'

    m_0_2147483647h = m_0.CDK(2147483647, hardened=True)
    m_0_2147483647hN = m_0_2147483647h.neutered()
    check_serialization(m_0_2147483647h)
    check_serialization(m_0_2147483647hN)

    assert str(m_0_2147483647h) == 'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9'
    assert str(m_0_2147483647hN) == 'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a'

    m_0_2147483647h_1 = m_0_2147483647h.CDK(1)
    m_0_2147483647h_1N = m_0_2147483647h_1.neutered()
    m_0_2147483647hN_1 = m_0_2147483647hN.CDK(1)
    check_serialization(m_0_2147483647h_1)
    check_serialization(m_0_2147483647h_1N)
    check_serialization(m_0_2147483647hN_1)

    assert str(m_0_2147483647h_1) == 'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef'
    assert str(m_0_2147483647h_1N) == 'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon'
    assert str(m_0_2147483647hN_1) == 'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon'

    m_0_2147483647h_1_2147483646h = m_0_2147483647h_1.CDK(2147483646, hardened = True)
    m_0_2147483647h_1_2147483646hN = m_0_2147483647h_1_2147483646h.neutered()
    check_serialization(m_0_2147483647h_1_2147483646h)
    check_serialization(m_0_2147483647h_1_2147483646hN)

    assert str(m_0_2147483647h_1_2147483646h) == 'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc'
    assert str(m_0_2147483647h_1_2147483646hN) == 'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL'

    m_0_2147483647h_1_2147483646h_2 = m_0_2147483647h_1_2147483646h.CDK(2)
    m_0_2147483647h_1_2147483646h_2N = m_0_2147483647h_1_2147483646h_2.neutered()
    m_0_2147483647h_1_2147483646hN_2 = m_0_2147483647h_1_2147483646hN.CDK(2)
    check_serialization(m_0_2147483647h_1_2147483646h_2)
    check_serialization(m_0_2147483647h_1_2147483646h_2N)
    check_serialization(m_0_2147483647h_1_2147483646hN_2)

    assert str(m_0_2147483647h_1_2147483646h_2) == 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'
    assert str(m_0_2147483647h_1_2147483646h_2N) == 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt'
    assert str(m_0_2147483647h_1_2147483646hN_2) == 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt'


def test_3():
    seed = bytes.fromhex('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be')
    m = ExtendedKey.from_seed(seed)
    check_serialization(m)
    M = m.neutered()
    check_serialization(M)

    assert str(m) == 'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6'
    assert str(M) == 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13'

    m_0h = m.CDK(0, hardened = True)
    check_serialization(m_0h)
    m_0hN = m_0h.neutered()
    check_serialization(m_0hN)

    assert str(m_0h) == 'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L'
    assert str(m_0hN) == 'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y'


def test_4():
    seed = bytes.fromhex('3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678')
    m = ExtendedKey.from_seed(seed)
    check_serialization(m)
    M = m.neutered()
    check_serialization(M)

    assert str(m) == 'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv'
    assert str(M) == 'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa'

    m_0h = m.CDK(0, hardened=True)
    check_serialization(m_0h)
    m_0hN = m_0h.neutered()
    check_serialization(m_0hN)

    assert str(m_0h) == 'xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G'
    assert str(m_0hN) == 'xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m'

    m_0h_1h = m_0h.CDK(1, hardened=True)
    check_serialization(m_0h_1h)
    m_0h_1hN = m_0h_1h.neutered()
    check_serialization(m_0h_1hN)

    assert str(m_0h_1h) == 'xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1'
    assert str(m_0h_1hN) == 'xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt'


def test_5():
    # all invalid
    #with pytest.raises(Exception) as e:

    invalid_keys = [ \
        'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm',\
        'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH',\
        'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn',\
        'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ',\
        'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4',\
        'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J',\
        'xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv',\
        'xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ',\
        'xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN',\
        'xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8',\
        'DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4',\
        'DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9',\
        'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx',\
        'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G',\
        'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY',\
        'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL']

    # TODO: check error messages

    for k in invalid_keys:
        try:
            m = ExtendedKey.import_format('xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm')
            fail = False
        except Exception as e:
            fail = True
            print(k, 'failed:', e)

        assert fail


def test_bip49():
    masterseedwords = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    masterkey = 'uprv8tXDerPXZ1QsVNjUJWTurs9kA1KGfKUAts74GCkcXtU8GwnH33GDRbNJpEqTvipfCyycARtQJhmdfWf8oKt41X9LL1zeD2pLsWmxEk3VAwd'

    m = Mnemonic.master_key(masterseedwords, network = 'testnet', scheme = 'P2SH(P2WPKH)')
    assert masterkey == m.export_format()

    # Account 0, root = m/49'/1'/0'
    m_49h_1h_0h = m.derivation_path("m/49'/1'/0'")

    account0Xpriv = \
    'uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n'
    assert m_49h_1h_0h.export_format() == account0Xpriv

    account0Xpub = \
    'upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY'
    assert m_49h_1h_0h.neutered().export_format() == account0Xpub


    # Account 0, first receiving private key = m/49'/1'/0'/0/0
    my0key = m_49h_1h_0h.derivation_path("m/0/0")
    my0pubkey = my0key.neutered().key

    account0recvPrivateKey = \
    'cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ'
    assert my0key.key.export_format(network='testnet') == account0recvPrivateKey
    account0recvPrivateKeyHex = \
    'c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8'
    assert my0key.key.hex() == account0recvPrivateKeyHex
    account0recvPublickKeyHex = \
    '03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f'
    assert my0pubkey.hex() == account0recvPublickKeyHex

    # Address derivation
    keyhash = '38971f73930f6c141d977ac4fd4a727c854935b3' # HASH160(account0recvPublickKeyHex)
    assert hash160(my0pubkey.serialize()).hex() == keyhash

    scriptSig = '001438971f73930f6c141d977ac4fd4a727c854935b3' # = <0 <keyhash>>
    addressBytes = '336caa13e08b96080a32b5d818d59b4ab3b36742' # = HASH160(scriptSig)

    # addressBytes base58check encoded for testnet
    address = '2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2' # = base58check(prefix | addressBytes)
    assert Address.p2pkh(my0pubkey)

def test_bip84():
    mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    m = Mnemonic.master_key(mnemonic, scheme='P2WPKH')

    rootpriv = 'zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5'
    rootpub  = 'zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF'
    assert m.export_format() == rootpriv
    assert m.neutered().export_format() == rootpub

    # Account 0, root = m/84'/0'/0'
    ac0 = m.derivation_path("m/84'/0'/0'")
    xpriv = 'zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE'
    xpub  = 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs'
    assert ac0.export_format()==xpriv
    assert ac0.neutered().export_format()==xpub


    # Account 0, first receiving address = m/84'/0'/0'/0/0
    myprivkey = ac0.derivation_path("m/0/0").key
    mypubkey = myprivkey.PubKey()

    privkey = 'KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d'
    pubkey  = '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c'
    address = 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'

    assert myprivkey.export_format()==privkey
    assert mypubkey.hex() == pubkey
    assert Address.p2wpkh(mypubkey, network = ac0.network()) == address

    # Account 0, second receiving address = m/84'/0'/0'/0/1
    myprivkey = ac0.derivation_path("m/0/1").key
    mypubkey = myprivkey.PubKey()

    privkey = 'Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy'
    pubkey  = '03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77'
    address = 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g'

    assert myprivkey.export_format()==privkey
    assert mypubkey.hex() == pubkey
    assert Address.p2wpkh(mypubkey, network = ac0.network()) == address

    # Account 0, first change address = m/84'/0'/0'/1/0
    myprivkey = ac0.derivation_path("m/1/0").key
    mypubkey = myprivkey.PubKey()

    privkey = 'KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF'
    pubkey  = '03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6'
    address = 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el'

    assert myprivkey.export_format()==privkey
    assert mypubkey.hex() == pubkey
    assert Address.p2wpkh(mypubkey, network = ac0.network()) == address

def test_dice_rolls():
    dice_roll = 10*'1' + 10*'2' + 10*'3' + 10*'4' + 10*'5'
    entropy = sha256(dice_roll.encode())

    mnemonic = Mnemonic.generate(entropy[:16])
    assert mnemonic == 'limit palace swing matter antique come sea canvas cigar decide damage sea'

    xpriv = Mnemonic.master_key(mnemonic)

    xpriv_str = xpriv.export_format()
    assert xpriv_str=='xprv9s21ZrQH143K466vGp3fvz8f57ZVX52WQuGMXG48XpcYAx3Yu12aYZg59nZRuuAskKNKj3dUxhdokYtDPVdgmLg76gQiFJV62r9y8Rp3vs5'

    fingerprint = xpriv.fingerprint().hex()
    assert fingerprint == '084f6082'

    # BIP44, legacy
    xpriv_derived = xpriv.derivation_path("m/44'/0'/0'")
    xpriv_derived.set_version(scheme='P2PKH')
    xpub_derived = xpriv_derived.neutered()

    assert xpriv_derived.export_format() == 'xprv9zYK9C7JKgDKQ3GCPSFMbZgJpESBKi5UnAnDSeYWe5PUmGG1kgojANiK3RZDBR7JESm8HnFGqrRNYXBvqoyoUMvMtU5j3BAAZec7tRUiWrq'
    assert xpub_derived.export_format() == 'xpub6DXfYheCA3mccXLfVTnMxhd3NGGfjAoL9PhpF2x8CQvTe4bAJE7yiB2ntgP4sZN33jgo4zradjW7Dq3n9K6Nb9d9jaBmAUcGWNqH6m6NmVs'

    # BIP49, wrapped segwit
    xpriv_derived = xpriv.derivation_path("m/49'/0'/0'")
    xpriv_derived.set_version(scheme='P2SH(P2WPKH)')
    xpub_derived = xpriv_derived.neutered()

    assert xpriv_derived.export_format() == 'yprvAJZ7VQBfL4Z9sbD9xmn7JBYgeuvHVQaei4UtYDBqVrQqyaTCWNksJue4TrR9hvCteDfumaGG1rAEmEGeX9yXYZyByviN2ScLPaMNcBbfzb2'
    assert xpub_derived.export_format() == 'ypub6XYTtuiZAS7T65Hd4oK7fKVRCwkmtsJW5HQVLbbT4BwprNnM3v57rhxYK8FrSTYEQ2i3SbG3JjH47W4W8HVyGvZ4BqKtwDRpvJ3ckVJ16jR'

    # BIP84 native segwit
    xpriv_derived = xpriv.derivation_path("m/84'/0'/0'")
    xpriv_derived.set_version(scheme='P2WPKH')
    xpub_derived = xpriv_derived.neutered()

    assert xpriv_derived.export_format() == 'zprvAcRp2V6yKuNxV5aJJsEMjCPgfYYqSqDKjFjxHN3Sxb7sCF64nPUJEb2YgYdzvzBoBLsBgX36iiR6GYtNpv6BTM6qQEexJqfFmc1g6HBsdah'
    assert xpub_derived.export_format() == 'zpub6qRARzdsAGwFhZemQtmN6LLRDaPKrHwB6UfZ5kT4Wver53RDKvnYnPM2XpGHDjdE2LDsB795FvugZRGDrufZv9jthRrvmfzVqot9GcctTjg'
