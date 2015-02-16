#!/usr/bin/python3
"""
A 128-bit implementation of the AES cipher (encryption only).
Reads a binary file from stdin and outputs the result on stdout.
Spec: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
"""

import binascii, sys
import rijndael


def add_round_key(state):
    """
    Combine each byte of the state with a block of the round key using bitwise
    XOR.
    """
    pass

def sub_bytes(state):
    """
    Perform a non-linear substitution step by replacing each byte with another
    according to a lookup table.
    """
    pass

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

def encrypt(key_exp, w, Nb, Nr):
    """
    Encrypt the binary data with the given key.
    Return the final state.
    """
    state = [[0] * 4 for i in range(Nb)] # Initialise state 4 x 4 byte matrix
    add_round_key(state, w[0][Nb-1])

    for i in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, w[i*Nb][(i+1)*Nb-1])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, w[Nr*Nb][(Nr+1)*Nb-1])

    return state

if __name__ == '__main__':
    key = bytearray(sys.stdin.buffer.read(KEY_LENGTH)) # Read the cipher key
    plain_text = bytearray(sys.stdin.buffer.read())    # Read the data to be encrypted

    Nb = 4  # Number of columns (32-bit words) comprising the state
    Nk = 4  # Number of 32-bit words comprising the cipher key
    Nr = 10 # Number of rounds
    key_exp = rijndael.expand_keys(key, Nb, Nk, Nr)

    print("Key:")
    print(binascii.hexlify(key))
    print("Plaintext:")
    print(binascii.hexlify(plain_text))
    print("Expanded key:")
    for word in (key_exp): print(word)

    # sys.stdout.buffer.write(key)
