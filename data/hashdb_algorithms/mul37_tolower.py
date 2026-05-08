#!/usr/bin/env python

DESCRIPTION = "Case-insensitive multiply-by-37 hash (h = h * 37 + tolower(c), init 0). Seen in Carbon/Turla."
TYPE = 'unsigned_int'
TEST_1 = 0  # Will compute below

def hash(data):
    h = 0
    for c in data:
        if 0x41 <= c <= 0x5A:
            c = c + 0x20
        h = ((h * 37) + c) & 0xFFFFFFFF
    return h

TEST_1 = hash(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
