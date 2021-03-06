#!/usr/bin/python3
"""
A 128-bit implementation of the AES cipher (encryption only).
Reads a binary file from stdin and outputs the result on stdout.
Spec: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
"""

import binascii, copy, random, sys
import rijndael, test

KEY_LENGTH = 16 # Key length in bytes


def generate_data(num_blocks, nb, randomise):
    """
    Generate the given amount of data in bytes.
    The first 16 bytes is the key, the rest is the data.
    If `randomise` is true, the data will be random, otherwise it will be 0.
    """
    data = []
    data_length = num_blocks * (nb ** 2) + KEY_LENGTH
    if randomise:
        for i in range(data_length):
            data.append(random.randint(0, 255))
    else:
        data = [0] * data_length
    data = bytearray(data)

    return(data)

def create_plain_states(plain_text, nb):
    """
    Split the given plain text into an array of states, padding
    is added as necessary.
    """
    text_length = len(plain_text)
    state_length = nb ** 2

    # Pad with 0s to make it divisible into nb x nb states
    diff = text_length % state_length
    if diff != 0: plain_text.extend([0] * (state_length - diff))

    # Split into multiple states if > state length
    states = [plain_text[x:x+state_length] for x in
            range(0, len(plain_text), state_length)]

    return states

def transpose_states(states, nb):
    """
    Transpose the state arrays to go by columns instead of rows (or vice versa).
    Slightly tricky since states are arrays and not matrices.
    """
    trans_states = []
    for state in states:
        # Create a matrix for easy transposing
        state = [state[i:i+4] for i in range(0, len(state), nb)]
        # Transpose matrix
        state = [list(i) for i in zip(*state)]
        # Merge rows into one array
        state = [b for row in state for b in row]
        trans_states.append(bytearray(state))

    return trans_states

def create_states(plain_text, nb):
    """
    Create array of states as padded and transposed byte arrays.
    """
    states = create_plain_states(plain_text, nb)
    return transpose_states(states, nb)

def create_cipher_text(states, nb):
    """
    Merge the encrypted states into cipher text.
    """
    # Transpose states back to original row order
    states = transpose_states(states, nb)
    # "byte for byte in state for state in states" in Python order
    return bytearray([byte for state in states for byte in state])

def rotate(arr, steps):
    """
    Rotate the array steps to the left (positive) or right (negative).
    """
    return arr[steps:] + arr[0:steps]

def add_round_key(state, key_exp, enc_round, offset, nk):
    """
    Combine each byte of the state with a block of the round key using bitwise
    XOR.
    """
    round_key = [0] * offset
    enc_round_offset = enc_round * offset
    # Extract the transpose key to get order as columns instead of rows
    for i in range(nk):
        for j in range(nk):
            round_key[j*nk+i] = key_exp[enc_round_offset+i*nk+j]

    # Column-wise XOR of state encryption key
    for i in range(offset): state[i] = state[i] ^ round_key[i]

def sub_bytes(state, offset):
    """
    Perform a non-linear substitution step by replacing each byte with another
    according to a lookup table.
    """
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

def encrypt(states, key_exp, nb, nk, nr):
    """
    Encrypt the binary data (states) with the given expanded key.
    Return the final states in a list.
    """
    # TODO Add IV for multiple blocks
    enc_states = []    # Encrypted states
    offset = (nb ** 2) # 'Matrix' offset
    for state in states:
        state = copy.copy(state)                 # Remove reference to old state
        add_round_key(state, key_exp, 0, offset, nk) # Initial key round

        for i in range(1, nr):
            sub_bytes(state, offset)
            shift_rows(state, nb)
            mix_columns(state, nb)
            add_round_key(state, key_exp, i, offset, nk)

        # Leave out MixColumns for final round
        sub_bytes(state, offset)
        shift_rows(state, nb)
        add_round_key(state, key_exp, nr, offset, nk)
        enc_states.append(state) # Save encrypted state

    return enc_states

if __name__ == '__main__':
    # test.run_tests() # Run tests first

    # key = bytearray(sys.stdin.buffer.read(KEY_LENGTH)) # Read the cipher key
    # plain_text = bytearray(sys.stdin.buffer.read())    # Read the data to be encrypted

    nb = 4  # Number of columns (32-bit words) comprising the state
    nk = 4  # Number of 32-bit words comprising the cipher key
    nr = 10 # Number of rounds

    data = generate_data(10 ** 6, nb, False)
    key = data[:KEY_LENGTH]
    plain_text = data[KEY_LENGTH:]

    # Expand encryption key
    key_exp = rijndael.expand_keys(key, nb, nk, nr)
    # Split plain text into states
    states = create_states(plain_text, nb)
    # Encrypt the plain text (states)
    states_enc = encrypt(states, key_exp, nb, nk, nr)
    # Append encrypted states into cipher text
    cipher_text = create_cipher_text(states_enc, nb)

    print("Nb (# state columns):", nb)
    print("Nk (# key words):    ", nk)
    print("Nr (# rounds):       ", nr)
    print("Key:")
    print(binascii.hexlify(key))
    print("Plain text:")
    print(binascii.hexlify(plain_text))
    print("States:")
    for state in states: print(binascii.hexlify(state))
    print("Expanded key:")
    print(binascii.hexlify(key_exp))
    print("Encrypted states:")
    for state in states_enc: print(binascii.hexlify(state))
    print("Cipher text:")
    print(binascii.hexlify(cipher_text))
    print()
    # Format text according to spec
    print("Formatted plain text:")
    print(str(binascii.hexlify(plain_text))[2:-1].upper())
    print("Formatted cipher text:")
    print(str(binascii.hexlify(cipher_text))[2:-1].upper())

    # Write the encrypted bytes to stdout
    # sys.stdout.buffer.write(cipher_text)
