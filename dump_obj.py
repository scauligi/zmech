#!/usr/bin/env python3

import sys
from pathlib import Path

from zmech import ZMech, zdecode


def main(fname, oidxs):
    z = ZMech(fname)
    z.load_abbrevs()

    table_start = z.readW(0x0A)
    print(f"object table is at address 0x{table_start:04x}")
    z.seek(table_start)
    first_proplistp = 0

    # defaults table is 31 words long
    print("Default properties:")
    default_props = {}
    for n in range(31, 0, -1):
        w = z.readW()
        if w:
            print(f"  {n:2}  0x{w:04x}")
        default_props[n] = w

    print("Object list:")
    all_objs = [None]
    for _ in range(255):
        if first_proplistp and z.tell() >= first_proplistp:
            break
        attrs = z.read(4)
        parent = z.readB()
        sibling = z.readB()
        child = z.readB()
        proplistp = z.readW()
        if not first_proplistp:
            first_proplistp = proplistp
        with z.seek(proplistp):
            textlength = z.readB()
            shortname = z.readZ(max=textlength)
            props = {}
            while True:
                szbyte = z.readB()
                if not szbyte:
                    break
                propnum = szbyte & 0b11111
                nbytes = (szbyte >> 5) + 1
                propdata = z.read(nbytes)
                props[propnum] = propdata
        all_objs.append(
            dict(
                attrs=attrs,
                parent=parent,
                sibling=sibling,
                child=child,
                shortname=shortname,
                props=props,
            )
        )

    if oidxs:
        for oidx in oidxs:
            obj = all_objs[oidx]
            print(' ', obj['shortname'])
            aa = int.from_bytes(obj['attrs'], 'big')
            attrs = []
            for n in range(8 * 4):
                if aa & (0x80000000 >> n):
                    attrs.append(f"{n:02x}")
            print('   ', '[' + ', '.join(attrs) + ']')
            for n, prop in obj['props'].items():
                print('   ', f"{n:02x}", ':', f"({len(prop)})", prop.hex(' ', 2))
    else:
        for idx, obj in enumerate(all_objs[1:], start=1):
            print(f"{idx:3} ", obj['shortname'])


if __name__ == '__main__':
    fname = 'zork1-r88-s840726.z3'
    oidxs = None
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    if len(sys.argv) > 2:

        def _xint(s):
            if s.startswith('0x'):
                return int(s, 16)
            return int(s)

        oidxs = map(_xint, sys.argv[2:])
    main(fname, oidxs)
