#!/usr/bin/python3
"""
Implementation of the Rijndael key schedule.
"""


def expand_keys(key):
    """
    Extract round keys using Rijndael's key schedule.
    """
    n = 16        # Bytes
    b = 176       # Bytes
    b_it = 0      # Counter for bytes of expanded key
    rcon_it = 1   # Iterator
    exp_key = key # Final expanded key

    t = b'0000' # 4-byte temp variable
