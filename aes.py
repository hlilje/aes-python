#!/usr/bin/python3
"""
A 128-bit implementation of the AES cipher (encryption only).
Reads a binary file from stdin and outputs the result on stdout.
Spec: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
"""

import binascii, copy, sys
import rijndael

KEY_LENGTH = 16 # Key length in bytes


def rotate(state, steps):
    """
    Rotate the state steps to the left (positive) or right (negative).
    """
    return state[steps:] + state[0:steps]

def add_round_key(state, key_exp, enc_round, offset):
    """
    Combine each byte of the state with a block of the round key using bitwise
    XOR.
    """
    round_offset = enc_round * offset
    round_key = key_exp[round_offset:round_offset+offset]
    # Column-wise XOR of state encryption key
    for i in range(offset): state[i] = state[i] ^ round_key[i]

def sub_bytes(state, enc_round, offset):
    """
    Perform a non-linear substitution step by replacing each byte with another
    according to a lookup table.
    """
    round_offset = enc_round * offset
    # Substitute with Sbox
    for i in range(offset): state[i] = rijndael.sbox[state[i]]

def shift_rows(state, nb):
    """
    Perform a transposition step where the last three rows of the state are
    shifted cyclically a certain number of steps.
    """
    # Shift columns increasing steps to the left except the first
    for i in range(nb):
        offset = i * nb
        state[offset:offset+nb] = rotate(state[offset:offset+nb], i)

def galois_mult(a, b):
    """
    Multiplication in the Galois field GF(2^8).
    """
    p = 0
    hi_bit_set = 0
    for i in range(8):
        if b & 1 == 1: p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set == 0x80: a ^= 0x1b
        b >>= 1
    return p % 256

def mix_column(column):
    """
    Mix one column by by considering it as a polynomial and performing
    operations in the Galois field (2^8).
    """
    # XOR is addition in this field
    temp = copy.copy(column) # Store temporary column for operations
    column[0] = galois_mult(temp[0], 2) ^ galois_mult(temp[1], 3) ^ \
                galois_mult(temp[2], 1) ^ galois_mult(temp[3], 1)
    column[1] = galois_mult(temp[0], 1) ^ galois_mult(temp[1], 2) ^ \
                galois_mult(temp[2], 3) ^ galois_mult(temp[3], 1)
    column[2] = galois_mult(temp[0], 1) ^ galois_mult(temp[1], 1) ^ \
                galois_mult(temp[2], 2) ^ galois_mult(temp[3], 3)
    column[3] = galois_mult(temp[0], 3) ^ galois_mult(temp[1], 1) ^ \
                galois_mult(temp[2], 1) ^ galois_mult(temp[3], 2)

def mix_columns(state, nb):
    """
    Perform a mixing operation which operates on the columns of the states,
    combining the four bytes in each column.
    """
    for i in range(nb):
        # Create column from the corresponding array positions
        column = []
        for j in range(nb): column.append(state[j*nb+i])

        # Mix the extracted column
        mix_column(column)

        # Set the new column in the state
        for j in range(nb): state[j*nb+i] = column[j]

def encrypt(plain_text, key_exp, nb, nr):
    """
    Encrypt the binary data with the given key.
    Return the final state.
    """
    offset = (nb ** 2)                       # 'Matrix' offset
    state = [0] * offset                     # Initialise state 'matrix'
    add_round_key(state, key_exp, 0, offset) # Initial key round

    for i in range(1, nr):
        sub_bytes(state, i, offset)
        shift_rows(state, nb)
        mix_columns(state, nb)
        add_round_key(state, key_exp, i, offset)

    sub_bytes(state, i, offset)
    shift_rows(state, nb)
    add_round_key(state, key_exp, nr, offset)

    return state

if __name__ == '__main__':
    key = bytearray(sys.stdin.buffer.read(KEY_LENGTH)) # Read the cipher key
    plain_text = bytearray(sys.stdin.buffer.read())    # Read the data to be encrypted

    nb = 4  # Number of columns (32-bit words) comprising the state
    nk = 4  # Number of 32-bit words comprising the cipher key
    nr = 10 # Number of rounds
    # Expanded encryption key
    key_exp = rijndael.expand_keys(key, nb, nk, nr)

    print("Key:")
    print(binascii.hexlify(key))
    print("Plaintext:")
    print(binascii.hexlify(plain_text))
    print("Expanded key:")
    print(binascii.hexlify(key_exp))

    encrypt(plain_text, key_exp, nb, nr)

    # sys.stdout.buffer.write(key)
