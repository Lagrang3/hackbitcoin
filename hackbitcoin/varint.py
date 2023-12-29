from .util import int_to_little_endian, little_endian_to_int

class varint:
    """See https://en.bitcoin.it/wiki/Protocol_documentation"""
    @staticmethod
    def parse(stream):
        """Read a varint from a stream"""
        i = stream.read(1)[0]
        if i==0xfd:
            # the next two bytes are the number
            return little_endian_to_int(stream.read(2))
        elif i==0xfe:
            # the next 4 bytes are the number
            return little_endian_to_int(stream.read(4))
        elif i==0xff:
            # the next 8 bytes are the number
            return little_endian_to_int(stream.read(8))
        else:
            return i


    @staticmethod
    def encode(i):
        """Encode an integer as varint"""
        if i<0xfd:
            return bytes([i])
        elif i<0x10000:
            return b'\xfd' + int_to_little_endian(i,2)
        elif i<0x100000000:
            return b'\xfe' + int_to_little_endian(i,4)
        elif i<0x10000000000000000:
            return b'\xff' + int_to_little_endian(i,8)
        else:
            raise ValueError('integer too large: {}'.format(i))
