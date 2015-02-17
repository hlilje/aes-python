#!/usr/bin/python3
"""
A 128-bit implementation of the AES cipher (encryption only).
Reads a binary file from stdin and outputs the result on stdout.
Spec: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
"""

import binascii, sys
import rijndael

KEY_LENGTH = 16 # Key length in bytes


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

def shift_rows(state):
    """
    Perform a transposition step where the last three rows of the state are
    shifted cyclically a certain number of steps.
    """
    pass

def mix_columns(state):
    """
    Perform a mixing operation which operates on the columns of the states,
    combining the four bytes in each column.
    """
    pass

def encrypt(plain_text, key_exp, nb, nr):
    """
    Encrypt the binary data with the given key.
    Return the final state.
    """
    offset = (nb ** 2)
    state = [0] * offset           # Initialise state 'matrix'
    add_round_key(state, key_exp, 0, offset) # Initial key round

    for i in range(1, nr):
        sub_bytes(state, i, offset)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_exp, i, offset)

    sub_bytes(state, i, offset)
    shift_rows(state)
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
