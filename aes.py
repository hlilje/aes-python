#!/usr/bin/python3
"""
A 128-bit implementation of the AES cipher (encryption only).
Reads a binary file from stdin and outputs the result on stdout.
Spec: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
"""

import binascii, sys
import rijndael
import helpers as hp

KEY_LENGTH = 16 # Key length in bytes


def add_round_key(state, w, enc_round, Nb):
    """
    Combine each byte of the state with a block of the round key using bitwise
    XOR.
    """
    l = enc_round * Nb # Word offset
    # Column-wise XOR of state with key words
    for i in range(Nb):
        col = bytearray()
        for j in range(Nb): col.append(state[j][i])
        col = hp.xor(col, w[l])
        for j in range(Nb): state[j][i] = col[j]
        l = l + 1

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

def encrypt(plain_text, w, Nb, Nr):
    """
    Encrypt the binary data with the given key.
    Return the final state.
    """
    state = [[0] * Nb for i in range(4)] # Initialise state 4 x Nb byte matrix
    print(state)
    add_round_key(state, w[0][Nb-1], 0, Nb)

    for i in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, w[i*Nb][(i+1)*Nb-1], i, Nb)

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, w[Nr*Nb][(Nr+1)*Nb-1], i, Nb)

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

    add_round_key([[1,1,1,1],[2,2,2,2],[3,3,3,3],[4,4,4,4]], key_exp, 0, Nb)

    # encrypt(plain_text, key_exp, Nb, Nr)

    # sys.stdout.buffer.write(key)
