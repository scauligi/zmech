#!/usr/bin/env python3

import itertools
from pathlib import Path

from attrs import define, field

from dump_code import Var, parse_routine
from zmech import ZMech

ATTRIBUTES = {
    0x03: "LONG_DESC_SEEN",
    0x0B: "OPEN",  # (as in (eb)[kitchen window] or bottle)
    0x1B: "BOAT",
}

# Props:
# 0x5: list-of-oidxs of interactables (eg stairs, chimney, window)
# 0xc: point score value? for taking? see @a3f0 in [a3e0]
# 0xd: point score value? eg for finding (a3)[large emerald]
# 0xe: paddr of out-in-world description for nouns
# 0x11 arg:
#   0x3: print long/first-visit description
#   0x4: print short/repeat-visit description (probably)
# 0x16: down
# 0x17: up
# 0x18: southwest
# 0x19: southeast
# 0x1a: northwest
# 0x1b: northeast
# 0x1c: south
# 0x1d: west
# 0x1e: east
# 0x1f: north

Var.map = {
    16: "loc",
    17: "score",
    79: "also_maybe_score",
    82: "isLight",
    114: "verb_parse_info?",
    116: "cmd_parse_info?",
    125: "intext",
    126: "parse",
    129: "nwords",
    134: "subject",
    135: "object",
    136: "verb",
    156: "foundSecretPath",
    173: "verbTable?",
}

# parse buffer:
#   b[maxw] b[nwords] blocks...
#   where block is w[&dictword|null] [wlen] [textidx]

# burn: 41 93 00
# eat:  41 a3 00
# find: 41 ac 00
# kiss: 41 ba 00
# look: 41 c2 00
# talk: 41 de 00

# ...
# [5a18]: bb where verb data is set
# $v116[0] <w- third byte of word data?
# $v116[2] <w- $v114 (another struct?)
# $v114[0] <w- $dict-addr-of-the-verb
# $v114[2] <b- wlen of the verb
# $v114[3] <b- textidx of the verb

# [5baa]: $pword $flag $???
#   tests first byte of $pword data for $flag
#   eg verb flag seems to be 0x40

# [644a]: $v1[0x7] -> $verb
#   also $v1 -> $v131

# so $v116[0], do 0xff - that, then loadW $v173[that] -> add 1 -> load that[0x7] -> sets $verb

# verb codes:
#   0x1a: clean? scrub?
#   0x1c: burn / set fire to
#   0x22: enter?
#   0x25: count?
#   0x2a:
#   0x2b: enter?
#   0x2d:
#   0x33: eat
#   0x38: look? or just initial description or something
#   0x3c: find or "where is"?
#   0x3f:
#   0x53:
#   0x56:
#   0x5d: love? kiss?
#   0x6f: talk (to)?
#   0x8b: boat-related?


@define
class Routine:
    header: int
    addr: int
    locals: list[int]
    insns: list
    bbs: set
    notes: list[str] = field(factory=list)


def main(fname):
    z = ZMech(fname)
    z.load()

    routines = {}
    remaining = set()

    # slurp call targets from props 0x2, 0x9, and 0x11
    for obj in z.objects.values():
        for prop in [0x2, 0x9, 0x11]:
            if prop in obj.props:
                assert len(obj.props[prop]) == 2
                dst = int.from_bytes(obj.props[prop], 'big') * 2
                if dst:
                    remaining.add(dst)

    # there's also a call site based off of loadw $v171 0x89
    # NOTE: there's another one based off of $v172 but I haven't figured it out yet
    dst = z.readW(z.gvar(171) + 0x89 * 2) * 2
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

    verbs = []
    dict_start = z.readW(0x08)
    z.seek(dict_start)
    n = z.readB()
    z.skip(n)
    l = z.readB()
    num = z.readW()
    for _ in range(num):
        w = z.readZ(max=2)
        d = z.read(l - 4)
        if d[0] & 0x40:
            wty = d[0]
            if wty & 0x3 == 0x1:
                it = d[1]
            else:
                it = d[2]
            it = 0xFF - it
            it = z.readW(z.gvar(173) + 2 * it)
            it = it + 1
            v = z.readB(it + 0x7)
            verbs.append((w, d, v))
    verbs.sort(key=lambda wdv: wdv[2])
    print('verb codes:')
    for v, wdv in itertools.groupby(verbs, key=lambda wdv: wdv[2]):
        print(f"[{v:02x}] {' '.join(w for w,d,_v in wdv)}")

    print()
    print()
    print()
    for obj in z.objects.values():
        for prop in [0x2, 0x9, 0x11]:
            if prop in obj.props:
                dst = int.from_bytes(obj.props[prop], 'big') * 2
                if dst:
                    r = routines[dst]
                    r.notes.append(f"({obj.idx:02x})[{obj.shortname}] prop {hex(prop)}")

    for vidx in sorted(Var.seen.difference(range(16))):
        if not z.gvar(vidx) and vidx not in Var.map:
            continue
        v = Var(vidx)
        print(f"{v}: {z.gvar(vidx):04x}")
    print(f"\nalso I found {len(routines)} routines")

    for rstart in sorted(routines):
        r = routines[rstart]
        print()
        print()
        print()
        for note in r.notes:
            print(f";; {note}")
        if r.header is not None:
            print(f"{r.header:04x} :", r.locals)
        for insn in r.insns:
            if insn.addr in r.bbs and insn is not r.insns[0]:
                print()
            print(insn)


def splat(z, oidx):
    o = z.objects[oidx]
    for p, v in o.props.items():
        if len(v) == 1:
            ooidx = int.from_bytes(v)
            if ooidx in z.objects:
                oo = z.objects[ooidx]
                print(hex(p), f"{ooidx:02x}", oo.shortname)


if __name__ == '__main__':
    fname = 'zork1-r88-s840726.z3'
    import sys

    if sys.flags.interactive:
        z = ZMech(fname)
        z.load()
    else:
        main(fname)
