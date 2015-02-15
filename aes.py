#!/usr/bin/python3
"""
An implementation of the AES cipher.
"""

import sys, binascii

KEY_LENGTH = 16 # Cipher key length in bytes
BLOCK_SIZE = 16 # Block size in bytes


if __name__ == '__main__':
    key = sys.stdin.buffer.read(KEY_LENGTH)
    print(binascii.hexlify(key))

    # sys.stdout.buffer.write(key)
