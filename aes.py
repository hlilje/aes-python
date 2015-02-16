#!/usr/bin/python3
"""
An bit implementation of the AES cipher. Reads a binary file from stdin and
outputs the result on stdout.
"""

import sys, binascii, rijndael

KEY_LENGTH = 16 # Cipher key length in bytes
BLOCK_SIZE = 16 # Block size in bytes


def add_round_key():
    """
    Combine each byte of the state with a block of the round key using bitwise
    XOR.
    """
    pass

def sub_bytes():
    """
    Perform a non-linear substitution step by replacing each byte with another
    according to a lookup table.
    """
    pass

def shift_rows():
    """
    Perform a transposition step where the last three rows of the state are
    shifted cyclically a certain number of steps.
    """
    pass

def mix_columns():
    """
    Perform a mixing operation which operates on the columns of the states,
    combining the four bytes in each column.
    """
    pass

def encrypt():
    """
    Encrypt the binary data with the given key.
    """
    pass

if __name__ == '__main__':
    key = bytearray(sys.stdin.buffer.read(KEY_LENGTH)) # Read the cipher key
    plain_text = bytearray(sys.stdin.buffer.read())    # Read the data to be encrypted
    state = [[0] * 4 for i in range(4)]                # Initialise state 4 x 4 byte matrix

    Nb = 4  # Number of columns (32-bit words) comprising the state
    Nk = 4  # Number of 32-bit words comprising the cipher key
    Nr = 10 # Number of rounds
    # key[4*Nk]
    w = [Nb*(Nr+1)]
    # rijndael.expand_keys(key, w, Nk, Nr)

    print(binascii.hexlify(key))
    print(binascii.hexlify(plain_text))

    # sys.stdout.buffer.write(key)
