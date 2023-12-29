from .hash import double_sha256

class base58:
    """Reference implementation:
    https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp"""
    pszBase58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    mapBase58=[ -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,]

    @staticmethod
    def encode(byte_stream):
        count = 0
        for c in byte_stream:
            if c==0:
                count+=1
            else:
                break
        n = int.from_bytes(byte_stream,'big')
        prefix = '1'*count
        result = ''
        while n>0:
            n,mod = divmod(n,58)
            result = base58.pszBase58[mod] + result
        return prefix + result


    @staticmethod
    def decode(char_stream):
        count = 0
        for c in char_stream:
            if c=='1':
                count+=1
            else:
                break
        n=0
        for c in char_stream:
            n = n*58 + base58.mapBase58[ord(c)]
        size = count + (n.bit_length()+7) //8
        return n.to_bytes(size,'big')


    @staticmethod
    def encode_checksum(byte_stream):
        return base58.encode(byte_stream+double_sha256(byte_stream)[:4])


    @staticmethod
    def decode_checksum(string):
        data = base58.decode(string)
        return data[:-4]


