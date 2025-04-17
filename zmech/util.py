def printd(*args, **kwargs):
    import zmech

    if zmech._DEBUG:
        print(*args, **kwargs)


def from_bytes(b, signed=False):
    return int.from_bytes(b, byteorder='big', signed=signed)


def to_bytes(val, nbytes):
    return val.to_bytes(nbytes, byteorder='big', signed=(val < 0))


def _s(n):
    n = _u(n)
    if n >= 0x8000:
        n -= 0x10000
    return n


def _u(n):
    return n % 0x10000
