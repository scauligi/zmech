#!/usr/bin/env python3

import sys
from pathlib import Path

from zmech import ZMech


def main(fname):
    z = ZMech(fname)

    table_start = z.readW(0x08)
    print(f"dictionary is at address 0x{table_start:04x}")
    z.seek(table_start)

    n = z.readB()
    print(f"{n = }  (", end=' ')
    for _ in range(n):
        zc = z.readB()
        print(f"{zc:02x}[{chr(zc)}]", end=' ')
    print(')')
    entry_length = z.readB()
    print(f"{entry_length = }")
    num_entries = z.readW()
    print(f"{num_entries = }")

    for _ in range(num_entries):
        w = z.readZ(max=2)
        addl = z.read(entry_length - 4)
        print(repr(w), f"({addl.hex()})")

    abbrev_start = z.readW(0x18)
    print(f"abbreviation table at address 0x{table_start:04x}")
    z.load_abbrevs()
    for idx, abbrev in enumerate(z.abbrevs):
        print(f"{idx:2} ", abbrev)


if __name__ == '__main__':
    fname = 'zork1-r88-s840726.z3'
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    main(fname)
