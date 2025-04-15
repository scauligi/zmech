#!/usr/bin/env python3

import sys
from pathlib import Path

from attrs import define, field

from zmech import Imm, Insn, Str, Var, ZMech, zdecode

BB_END = "ret jump rtrue rfalse print_ret restore restart ret_popped quit".split()


def parse_routine(z, addr):
    insns = []
    seen = set()
    rstarts = set()
    jumps = set()
    z.seek(addr)
    while True:
        insn = z.readInsn()
        if not insn:
            break
        insns.append(insn)
        seen.add(insn.addr)
        if insn.name == "call" and insn.dst:
            rstarts.add(insn.args[0].value * 2)
        elif insn.dst is not None:
            jumps.add(insn.dst)
        if insn.name in BB_END:
            if seen.issuperset(jumps):
                break
    return insns, rstarts, jumps


def main(fname, start=None):
    z = ZMech(fname)
    z.load()

    routines = {}
    rargs = {}
    remaining = [start or z.init_pc]
    is_routine = start is not None

    while remaining:
        rstart = remaining.pop()
        if is_routine:
            rargs[rstart] = []
            z.seek(rstart)
            nargs = z.readB()
            for _ in range(nargs):
                rargs[rstart].append(z.readW())
            addr = z.tell()
        else:
            addr = rstart
        insns, rstarts, jumps = parse_routine(z, addr)
        is_routine = True
        routines[rstart] = (insns, jumps)
        for rstart in rstarts:
            if rstart not in routines and rstart not in remaining:
                remaining.append(rstart)

    print(f"Starting point: [{start or z.init_pc:04x}]")
    for rstart in sorted(routines):
        insns, jumps = routines[rstart]
        print()
        print()
        print()
        if rstart in rargs:
            print("== [", end=' ')
            for a in rargs[rstart]:
                print(f"{a:04x}", end=' ')
            print("] ==")
        else:
            print("== [ - ] ==")
        for insn in insns:
            if insn.addr in jumps and insn != insns[0]:
                print()
            print(insn)


if __name__ == '__main__':
    fname = 'zork1-r88-s840726.z3'
    start = None
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    if len(sys.argv) > 2:
        start = int(sys.argv[2], 16)
    main(fname, start)
