# Elliptic curve cryptography.

from .secp256k1 import secp256k1_Point, secp256k1_Field, secp256k1_Point
from .base58 import base58
from .hash import double_sha256, sha256, hmac_sha256
from .network import Network
from .util import int_to_little_endian, big_endian_to_int, int_to_big_endian


class PubKey:
    def __eq__(self,other):
        return self.point == other.point and self.compressed==other.compressed

    def __init__(self, point=None, compressed=True):
        """Default constructor, though a Pubkey is meant to be constructed
        either from a privKey or from byte stream."""
        if point is None:
            self.point = secp256k1_Point.identity()
        else:
            self.point = point
        self.compressed  =  compressed

    def __add__(self, other):
        return self.__class__(self.point + other.point)

    @classmethod
    def from_PrivKey(cls,k):
        point = k.secret * secp256k1_Point.generator()
        compressed = k.compressed
        return cls(point,compressed)

    def serialize(self):
        """Public key serialization by SEC (Standard for Efficienty Cryptography)"""
        if self.compressed:
            if self.point.y.num%2 == 0:
                return b'\x02'+self.point.x.num.to_bytes(32,'big')
            else:
                return b'\x03'+self.point.x.num.to_bytes(32,'big')
        else:
            return b'\x04' \
            +self.point.x.num.to_bytes(32,'big') \
            +self.point.y.num.to_bytes(32,'big')

    @classmethod
    def parse(cls,sec_bin):
        """Deserialization"""
        if not(sec_bin[0]==2 or sec_bin[0]==3 or sec_bin[0]==4):
            raise ValueError('Invalid serialized PubKey format')
        x = secp256k1_Field(int.from_bytes(sec_bin[1:33],'big'))
        if sec_bin[0]==4:
            compressed = False
            y = secp256k1_Field(int.from_bytes(sec_bin[33:65],'big'))
            point = secp256k1_Point(x,y,check=True)
        else:
            compressed = True
            is_even = bool(sec_bin[0]==2)
            point = secp256k1_Point.lift(x,is_even)
        return cls(point,compressed=compressed)


    def hex(self):
        return self.serialize().hex()

    def __repr__(self):
        return self.hex()


class PrivKey:
    def PubKey(self):
        return PubKey.from_PrivKey(self)

    def __eq__(self,other):
        return self.secret == other.secret and self.compressed==other.compressed

    def __init__(self,secret, compressed=True):
        self.secret = secret
        self.compressed = compressed

    def wif(self, network='mainnet'):
        """Wallet Import Format (WIF) human readable serialization of the
        private key.
        https://en.bitcoin.it/wiki/Wallet_import_format"""
        prefix = Network.wif_prefix(network)
        if self.compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        data = self.secret.to_bytes(32,'big')
        return base58.encode_checksum(prefix + data + suffix)

    @classmethod
    def from_wif(cls,wif):
        # first byte flags the network: mainnet, testnet, etc
        mybytes = base58.decode_checksum(wif)
        network = Network.wif_prefix_decode(mybytes[0:1])
        mybytes = mybytes[1:]
        n = int.from_bytes(mybytes[:32],'big')
        if len(mybytes)>32:
            compressed = True
        else:
            compressed = False
        return cls(n,compressed), network

    def export_format(self, network: str = 'mainnet'):
        '''
        Human readable.
        '''
        return self.wif(network = network)

    @classmethod
    def import_format(cls, wif):
        return cls.from_wif(wif)

    def __repr__(self):
        return self.write()

    def serialize(self,network='mainnet'):
        '''
        Write to binary.
        '''
        return int_to_big_endian(self.secret, 32)

    def hex(self):
        return self.serialize().hex()

    @classmethod
    def parse(cls, data):
        '''
        Read from binary.
        '''
        return cls(big_endian_to_int(data))

    def __add__(self, other):
        x = (self.secret + other.secret) % secp256k1_Point.N
        return self.__class__(x)

class Signature:
    """Elliptic curve secp256k1 signature (data only)."""

    def __init__(self,r,s):
        self.r=r
        self.s=s


    def __repr__(self):
        return 'Signature({:x},{:x})'.format(self.r,self.s)


    def serialize(self):
        """Distinguished Encoding Rules (DER) serialization."""
        def der_bin(num):
            nbin = num.to_bytes(32,'big')
            nbin.lstrip(b'\x00')
            if nbin[0]>=0x80:
                nbin = b'\x00'+nbin
            return bytes([0x02,len(nbin)]) + nbin
        rbin = der_bin(self.r)
        sbin = der_bin(self.s)
        return bytes([0x30,len(rbin)+len(sbin)]) +  rbin + sbin


    def __eq__(self,other):
        return self.r == other.r and self.s == other.s


    @classmethod
    def parse(cls,der_bin):
        assert der_bin[0]==0x30
        pair_len = der_bin[1]
        der_bin = der_bin[2:]
        assert len(der_bin)==pair_len

        def get_num(stream):
            assert stream[0]==0x02
            nlen = stream[1]
            stream = stream[2:]
            n = int.from_bytes(stream[:nlen],'big')
            stream = stream[nlen:]
            return n,stream
        r,der_bin = get_num(der_bin)
        s,der_bin = get_num(der_bin)
        return cls(r,s)


class ecdsa:
#   ECDSA works as follows: the signer holds a secret key e and announces his
#   public key P such that
#
#       e*G = P
#
#   the signer needs to prove that he knows the secret e without revealing it.
#   For example, if r*G = R is a fixed target agreed beforehand, then only
#   the owner of e can provide a pair of number (a,b) such that
#
#       a*G + b*P = R
#
#   this is because solving that equation is equivalent to solving the discrete
#   logarithm problem.
#
#   1. However, r must remain hidden otherwise the secret key is
#   revealed by solving the linear equation
#
#       a + b*e = r
#
#   2. On the other hand R must be implicit in the equation otherwise anyone can
#   choose any pair (a,b) and compute R.
#   Instead one can propose to solve the following equation
#
#       a*G + Rx * P = s*R
#
#   and ask the signer to provide a, Rx and s that solves the equation.
#
#   3. But there are two many free variables here, so that anyone can generate a
#   random pair (u,v), and compute R
#
#       u*G + v*P = R
#
#   then define
#
#       s = Rx/v,
#       a = u*s
#
#   4. therefore the value of a=m is fixed and agreed upon beforehand and the
#   equation required to solve is again of the form
#
#       m*G + Rx*P = s*R
#
#   but in this case the signer must provide R and s.
#
#   5. [SIGNING]
#   The equation is easily solved by the signer, the signing process involves
#   computing a random number r, then
#
#       R = r*G
#
#   then s is obtained from the linear equation
#
#       m + Rx*e = s*r
#
#       s = (m+Rx*e)/r
#
#   6. [VERIFICATION]
#   The verification takes only to verify that the equality holds
#
#       m*G + Rx*P = s*R
#
#   7. Because the signature (Rx,s) depends on the value of m, and can only be
#   generated by the owner of the secret e, ECDSA can be used to verify
#   ownership of the secret and to tamper proof on the data m.
#
#   8. In practice the validity of the signature is verified if
#
#       (m*G + Rx*P).x = (s*R).x
#
#   therefore (-s) is as good as (s) for a valid signature, because it only
#   changes the sign of (s*R).y which is not checked.

    @staticmethod
    def verify_signature(pub,m: int,sig):
        """Verify a EC signature.
        pub: public key
        m: message hash,
        sig: signature"""

        N = secp256k1_Point.N
        G = secp256k1_Point.generator()
        P = pub.point

        s_inv = pow(sig.s,N-2,N)
        u = (m*s_inv )% N
        v = (sig.r*s_inv )% N
        R = u*G + v*P
        return R.x.num == sig.r

    @staticmethod
    def sign(priv,m: int):
        """Produce a EC signature.
        priv: private key
        m: message hash"""

        N = secp256k1_Point.N
        G = secp256k1_Point.generator()

        r = ecdsa.deterministic_nounce(priv,m)
        Rx = (r*G).x.num
        r_inv = pow(r,N-2,N)
        s = ((m+Rx*priv.secret)*r_inv )% N
        # Both s and -s are valid signatures, choose the lowest value to avoid
        # malleability
        if s>N//2:
            s = N-s
        return Signature(Rx,s)

    @staticmethod
    def deterministic_nounce(priv,m):
        """RFC 6979. Deterministic ephemeral key generation for ECDSA.
        priv: private key
        m: message hash"""
        # FIXME: this needs testing and reviewing, otherwise you risk to leak
        # your private key
        N = secp256k1_Point.N

        k = b'\x00'*32
        v = b'\x01'*32
        if m>=N or m<0:
            m = m % N
        m_bytes = m.to_bytes(32,'big')
        secret_bytes = priv.secret.to_bytes(32,'big')

        k = hmac_sha256(secret = k, message = v+b'\x00'+secret_bytes+m_bytes)
        v = hmac_sha256(secret = k, message = v)

        k = hmac_sha256(secret = k, message = v+b'\x01'+secret_bytes+m_bytes)
        v = hmac_sha256(secret = k, message = v)
        while True:
            v = hmac_sha256(secret = k, message = v)
            candidate = int.from_bytes(v,'big')
            if candidate>=1 and candidate<N:
                return candidate
            k = hmac_sha256(secret = k, message = v+b'\x00')
            v = hmac_sha256(secret = k, message = v)
