#!/usr/bin/env python3

from pathlib import Path

from attrs import define, field

from dump_code import parse_routine
from zmech import ZMech


@define
class Routine:
    header: int
    addr: int
    locals: list[int]
    insns: list
    bbs: set


def main(fname):
    z = ZMech(fname)
    z.load()

    routines = {}
    remaining = set()

    # slurp call targets from props 0x15 and 0x1d
    for obj in z.objects.values():
        for prop in [0x15, 0x1D]:
            if prop in obj.props:
                assert len(obj.props[prop]) == 2
                dst = int.from_bytes(obj.props[prop], 'big') * 2
                if dst:
                    remaining.add(dst)

    insns, rstarts, jumps = parse_routine(z, z.init_pc)
    r = Routine(None, z.init_pc, None, insns, jumps)
    routines[z.init_pc] = r
    remaining.update(rstarts)

    while remaining:
        rstart = remaining.pop()
        z.seek(rstart)
        args = []
        nargs = z.readB()
        for _ in range(nargs):
            args.append(z.readW())
        addr = z.tell()
        insns, rstarts, jumps = parse_routine(z, addr)
        r = Routine(rstart, addr, args, insns, jumps)
        routines[rstart] = r
        remaining.update(rstarts.difference(routines))

    for rstart in sorted(routines):
        r = routines[rstart]
        print()
        print()
        print()
        if r.header is not None:
            print(f"{r.header:04x} :", r.locals)
        for insn in r.insns:
            if insn.addr in r.bbs and insn is not r.insns[0]:
                print()
            print(insn)


if __name__ == '__main__':
    fname = 'hitchhiker-r59-s851108.z3'
    main(fname)
