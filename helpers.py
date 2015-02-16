#!/usr/bin/python3
"""
Various helper functions.
"""


def xor(n, m):
    """
    Perform byte-wise XOR of two bytearrays (n XOR m) if m is a bytearray,
    otherwise of a bytearray n and a scalar m.
    """
    if isinstance(m, bytearray):
        return bytearray([n[i] ^ m[i] for i in range(len(n))])
    else:
        return bytearray([n[i] ^ m for i in range(len(n))])
