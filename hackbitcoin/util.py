def little_endian_to_int(mybytes):
    return int.from_bytes(mybytes,'little')

def big_endian_to_int(mybytes):
    return int.from_bytes(mybytes,'big')

def int_to_little_endian(i,nbytes):
    return i.to_bytes(nbytes,'little')

def int_to_big_endian(i,nbytes):
    return i.to_bytes(nbytes,'big')
