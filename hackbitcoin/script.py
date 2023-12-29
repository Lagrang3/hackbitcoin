# from .ecc import PubKey, Signature, ecdsa
from .varint import varint
from .hash import sha256, hash160
from .util import little_endian_to_int, int_to_little_endian, big_endian_to_int
from .ecc import PubKey, Signature, ecdsa
from io import BytesIO

class Script:
    FALSE = bytes()
    TRUE = bytes.fromhex('01')

    OP_0 = 0x00

    OP_RETURN = 0x6a
    OP_DUP = 0x76
    OP_EQUALVERIFY = 0x88
    OP_HASH160 = 0xa9
    OP_HASH256 = 0xaa
    OP_CHECKSIG = 0xac

    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e

    code_name = {
        OP_0 : "OP_0",

        OP_DUP: "OP_DUP",
        OP_EQUALVERIFY : "OP_EQUALVERIFY",
        OP_HASH160 : "OP_HASH160",
        OP_HASH256 : "OP_HASH256",
        OP_CHECKSIG : "OP_CHECKSIG",
        OP_RETURN: "OP_RETURN",

        OP_PUSHDATA1 : "OP_PUSHDATA1",
        OP_PUSHDATA2 : "OP_PUSHDATA2",
        OP_PUSHDATA4 : "OP_PUSHDATA4",
    }

    def fop_dup(self, stack, *args, **kwargs):
        if len(stack)<1:
            self.debug_message += \
                "OP_DUP needs 1 elements on stack" \
                + " {} found".format(len(stack))
            return False
        stack.append(stack[-1])
        return True

    def fop_hash160(self, stack, *args, **kwargs):
        if len(stack)<1:
            self.debug_message += \
                "OP_HASH160 needs 1 elements on stack" \
                + " {} found".format(len(stack))
            return False
        e = stack.pop()
        h = hash160(e)
        assert self.is_data(h)
        stack.append(h)
        return True

    def fop_hash256(self, stack, *args, **kwargs):
        if len(stack)<1:
            self.debug_message += \
                "OP_HASH256 needs 1 elements on stack" \
                + " {} found".format(len(stack))
            return False
        e = stack.pop()
        h = hash256(e)
        assert self.is_data(h)
        stack.append(h)
        return True

    def fop_checksig(self, stack, *args, **kwargs):
        if len(stack)<2:
            self.debug_message += \
                "OP_CHECKSIG needs 2 elements on stack" \
                + " {} found".format(len(stack))
            return False
        try:
            raw_puk = stack.pop()
            raw_sig = stack.pop()
            puk = PubKey.parse(raw_puk)
            sig = Signature.parse(raw_sig[:-1])
            sighash_flag = raw_sig[-1]
        except Exception as e:
            self.debug_message += "OP_CHECKSIG error: {}, ".format(str(e))
            self.debug_message += \
                "pubkey: {}, signature: {}".format(raw_puk.hex(),raw_sig.hex())
            return False
        ok = ecdsa.verify_signature( \
            puk, \
            big_endian_to_int(self.fun_sighash(sighash_flag)), \
            sig)
        if ok:
            self.debug_message += "OP_CHECKSIG: result is TRUE, "
            stack.append(Script.TRUE)
        else:
            self.debug_message += "OP_CHECKSIG: result is FALSE, "
            stack.append(Script.FALSE)
        return True

    def fop_equalverify(self,stack, *args, **kwargs):
        if len(stack)<2:
            self.debug_message += \
                "OP_EQUALVERIFY needs 2 elements on stack" \
                + " {} found".format(len(stack))
            return False
        A = stack.pop()
        B = stack.pop()
        if A!=B:
            self.debug_message += "OP_EQUALVERIFY: result is HALT, "
            return False
        return True

    def fop_return(self,*args,**kwargs):
        self.debug_message += "hit OP_RETURN"
        return False

    code_function = {
        OP_RETURN: fop_return,
        OP_DUP: fop_dup,
        OP_EQUALVERIFY: fop_equalverify,
        OP_HASH160: fop_hash160,
        OP_HASH256: fop_hash256,
        OP_CHECKSIG: fop_checksig
    }

    def __init__(self,data = None):
        self.data = data

    @classmethod
    def parse(cls,stream):
        length = varint.parse(stream)
        data = stream.read(length)
        return cls(data)

    def serialize(self):
        data = self.data
        return varint.encode(len(data)) + data

    def hex(self):
        return self.serialize().hex()

    def __add__(self,other):
        if isinstance(other, type(self)):
            return self.__class__(self.data + other.data)
        # elif isinstance(other, bytes):
        #     return self.__class__(self.data + other)
        # elif isinstance(other, int):
        #     return self.__class__(self.data + int_to_little_endian(other, 1))
        raise ValueError('Cannot add these two types')

    @classmethod
    def is_data(cls,opcode):
        if isinstance(opcode,int):
            return False
        if isinstance(opcode,bytes):
            return True
        raise ValueError('Opcode is not int nor bytes')

    @classmethod
    def _write_next(cls,op):
        # a code
        if not cls.is_data(op):
            return int_to_little_endian(op,1)

        data = op
        n = len(data)
        if n<cls.OP_PUSHDATA1:
            return int_to_little_endian(n,1) + data

        if n<0xff:
            return int_to_little_endian(cls.OP_PUSHDATA1) + \
                int_to_little_endian(n,1) + data

        if n<0xffff:
            return int_to_little_endian(cls.OP_PUSHDATA2) + \
                int_to_little_endian(n,2) + data

        if n<0xffffffff:
            return int_to_little_endian(cls.OP_PUSHDATA4) + \
                int_to_little_endian(n,4) + data

        raise ValueError('we should not arrive to this point')

    @classmethod
    def _read_next(cls,stream):
        b = stream.read(1)

        if len(b)==0:
            return None

        # is this data?
        n = little_endian_to_int(b)
        if n==0:
            return FALSE

        if n>=1 and n<cls.OP_PUSHDATA1:
            value = stream.read(n)
            if len(value)!= n:
                return None
            return value

        if n==cls.OP_PUSHDATA1:
            r = stream.read(1)
            if len(r)!= 1:
                return None
            n = little_endian_to_int(r)
            value = sream.read(n)
            if len(value)!=n:
                return None
            return value

        if n==cls.OP_PUSHDATA2:
            r = stream.read(2)
            if len(r)!=2:
                return None
            n = little_endian_to_int(r)
            value = sream.read(n)
            if len(value)!=n:
                return None
            return value

        if n==cls.OP_PUSHDATA4:
            r = stream.read(4)
            if len(r)!=4:
                return None
            n = little_endian_to_int(r)
            value = sream.read(n)
            if len(value)!=n:
                return None
            return value

        # it's not data, it is an operator
        return little_endian_to_int(b)

    def opcodes(self):
        codes = []
        stream = BytesIO(self.data)
        while True:
            op = self._read_next(stream)
            if op is None:
                break
            else:
                codes.append(op)
        return codes

    @classmethod
    def from_opcodes(cls, codes):
        data = cls.FALSE
        for op in codes:
            data += cls._write_next(op)
        return cls(data)


    @classmethod
    def _print_opcode(cls,opcode):
        if not cls.is_data(opcode):
            if not opcode in cls.code_name:
                raise ValueError('Opcode 0x{:x} is not registered'.format(opcode))
            return cls.code_name[opcode]
        return opcode.hex()


    def __repr__(self):
        codes = self.opcodes()
        return " ".join([ self._print_opcode(c) for c in codes ])


    def evaluate(self, fun_sighash):
        """
        fun_sighash: transaction hash getter
        """
        self.debug_message = ""
        self.fun_sighash = fun_sighash

        stack = list()
        cmd = self.opcodes()
        for c in cmd:
            if self.is_data(c):
                stack.append(c)
                continue

            if not c in self.code_function:
                raise ValueError('Opcode 0x{:x} is not implemented'.format(c))

            result = self.code_function[c](self,stack)
            if not result:
                return False

        # an empty stack is failure
        if len(stack)==0:
            self.debug_message += "Stack is empty at end of script."
            return False
        o = stack.pop()
        # an empty data on the stack is also failure
        if o == self.FALSE:
            self.debug_message += "Top element is FALSE."
            return False
        return True
