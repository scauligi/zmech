#!/usr/bin/env python3

import copy
import itertools
from collections import defaultdict as ddict

from attrs import define, field

from dump_code import BB_END
from zmech import ZMech
from zmech.structs import Imm, Var

ATTRIBUTES = {
    0x03: "LONG_DESC_SEEN",
    0x06: "ROOM?",
    0x0B: "OPEN",  # (as in (eb)[kitchen window] or bottle)
    0x1B: "BOAT",
}

# Props:
# 0x5: list-of-oidxs of interactables (eg stairs, chimney, window)
# 0xb: first-encounter text?
# 0xc: point score value? for taking? see @a3f0 in [a3e0]
# 0xd: point score value? eg for finding (a3)[large emerald]
# 0xe: paddr of out-in-world description for nouns
# 0x11 arg:
#   0x3: print long/first-visit description
#   0x4: print short/repeat-visit description (probably)
#   0x6: perform "take" failure?
# DIRECTIONS: len 1 => obj, len 2 => string to print instead
#   see [8aa4], seems to be the "go in X direction" routine
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
    0: "stack",
    16: "loc",
    17: "score",
    18: "turns",
    33: "openedCanary",
    79: "also_maybe_score",
    82: "isLight",
    86: "verbosity_superBrief",
    87: "verbosity_maximum",
    114: "verb_parse_info?",
    116: "cmd_parse_info?",
    125: "intext",
    126: "parse",
    127: "you",
    129: "nwords",
    134: "subject",
    135: "object",
    136: "verb",
    148: "tick_table",
    156: "foundSecretPath",
    171: "verbDispatch171",
    172: "verbDispatch172",
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
    header: int | None
    locals: list[int] = field(factory=list)
    args: int | None = None
    insns: list = field(factory=list)
    bbs: set = field(factory=set)
    calls: list['Insn'] = field(factory=list)
    notes: list[str] = field(factory=list)


def parse_routine(z, addr, is_start=False):
    r = Routine(addr if not is_start else None)
    with z.seek(addr):
        if not is_start:
            nargs = z.readB()
            r.locals.extend(z.readW() for _ in range(nargs))
        seen = set()
        while True:
            insn = z.readInsn()
            if not insn:
                break
            r.insns.append(insn)
            seen.add(insn.addr)
            if insn.name == "call" and insn.dst:
                r.calls.append(insn)
            elif insn.dst is not None:
                r.bbs.add(insn.dst)
            if insn.name in BB_END:
                if seen.issuperset(r.bbs) and z.tell() not in (0x6E4B, 0x8497):
                    break
    return r


def slurp_verbs(z):
    verbs = []
    dict_start = z.readW(0x08)
    with z.seek(dict_start):
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
    verbs_by_code = {}
    for v, wdv in itertools.groupby(verbs, key=lambda wdv: wdv[2]):
        verbs_by_code[v] = [w for w, d, v in wdv]
    swaps = [(0x22, "enter"), (0x2B, "open"), (0x40, "give"), (0x7D, "swim")]
    for code, verb in swaps:
        ww = verbs_by_code[code]
        idx = ww.index(verb)
        ww[0], ww[idx] = ww[idx], ww[0]
        verbs_by_code[code] = ww
    return verbs_by_code


def print_insn(insn, verbs_by_code):
    if insn.name == "je" and str(insn.args[0]) == '$verb':
        insn = copy.copy(insn)
        for i in range(1, len(insn.args)):
            a = insn.args[i]
            if isinstance(a, Imm):
                if a.value in verbs_by_code:
                    insn.args[i] = verbs_by_code[a.value][0].upper()
    print(insn.pretty())


def main(fname):
    z = ZMech(fname)
    z.load()

    routines = {}

    max_oidx = (z.obj(1)._plist - z.obj(1)._addr) // (z.obj(2)._addr - z.obj(1)._addr)

    notes_to_add = ddict(list)
    call_args = ddict(int)

    gvar_setters = ddict(list)

    # slurp call targets from props 0x2, 0x9, and 0x11
    for oidx in range(1, max_oidx + 1):
        obj = z.obj(oidx)
        for prop in obj.props():
            if prop.num in [0x2, 0x9, 0x11]:
                if dst := prop.paddr:
                    notes_to_add[dst].append(
                        f"({obj.idx:02x})[{obj.shortname}] prop {hex(prop.num)}"
                    )
                    if prop.num == 0x11:
                        call_args[dst] = 1

    verbs = slurp_verbs(z)

    for verbCode in range(0, 0x91 + 1):
        dst = z.readW((z.gvar(171), verbCode)) * 2
        if dst:
            if verbCode in verbs:
                vv = verbs[verbCode][0].upper()
            else:
                vv = f"{verbCode:02x}"
            notes_to_add[dst].append(f"from [5869]: loadw $v171 [verb:{vv}] -> call")

    for verbCode in range(0, 0x91 + 1):
        dst = z.readW((z.gvar(172), verbCode)) * 2
        if dst:
            if verbCode in verbs:
                vv = verbs[verbCode][0].upper()
            else:
                vv = f"{verbCode:02x}"
            notes_to_add[dst].append(f"from [5817]: loadw $v172 [verb:{vv}] -> call")

    z.seek(z.himem)
    if z.tell() % 2 == 1:
        z.skip(1)
    while z.tell() < 0x10B16:
        r = parse_routine(z, z.tell())
        routines[r.header] = r
        for call in r.calls:
            callhdr = call.args[0].value * 2
            notes_to_add[callhdr].append(f"called by [{r.header:04x}]: {call.pretty()}")
            call_args[callhdr] = max(call_args[callhdr], len(call.args[1:]))
        z.seek(r.insns[-1].end)
        if z.tell() % 2 == 1:
            z.skip(1)
    try:
        while True:
            a = z.tell()
            routines[a] = z.readZ()
    except EOFError:
        pass

    notes_to_add[0x54C4].append("turn_ticker")

    for dst, notes in notes_to_add.items():
        if dst in routines:
            routines[dst].notes.extend(notes)
        else:
            print(f"not found: [{dst:04x}]")

    for dst, nargs in call_args.items():
        r = routines[dst]
        r.args = min(nargs, len(r.locals))

    for _, r in sorted(routines.items()):
        if not isinstance(r, Routine):
            continue
        for insn in r.insns:
            v = None
            if insn.out:
                v = insn.out.idx
            elif insn.name in ("store", "inc", "dec", "inc_chk", "dec_chk"):
                if isinstance(insn.args[0], Imm):
                    v = insn.args[0].value
            if v and 16 <= v < 256:
                gvar_setters[v].append(insn)

    for vidx in range(16, 256):
        if not z.gvar(vidx) and vidx not in Var.map and vidx not in gvar_setters:
            continue
        v = Var(vidx)
        print(f"{v}: {z.gvar(vidx):04x}", end='')
        if vidx in gvar_setters:
            setters = ' '.join(f"[{insn.addr:04x}]" for insn in gvar_setters[vidx])
            print(f"  ; {setters}", end='')
        print()
    print(
        f"\nalso I found {len([r for r in routines.values() if isinstance(r, Routine)])} routines"
    )
    print()
    print()
    print()

    for rstart in sorted(routines):
        r = routines[rstart]
        if not isinstance(r, Routine):
            r = r.replace('"', '\\"')
            print(f'{rstart:04x} : "{r}"')
            continue
        for note in r.notes:
            print(f";; {note}")
        if r.args is not None:
            frags = [f"{r.header:04x} :"]
            # print(f"{r.header:04x} :", r.locals[:r.args], r.locals[r.args:])
            args = []
            for n in range(1, r.args + 1):
                Var.map[n] = f'arg{n}'
                if r.locals[n - 1]:
                    args.append(f"$arg{n}={r.locals[n-1]}")
                else:
                    args.append(f"$arg{n}")
            args = ', '.join(args)
            frags.append(f"({args})")
            for n in range(r.args + 1, len(r.locals) + 1):
                Var.map[n] = f'local{n}'
                if r.locals[n - 1]:
                    frags.append(f" $local{n} = {r.locals[n-1]}")
            print(' '.join(frags))
        else:
            print(f"{r.header:04x} :", r.locals)
            for n in range(1, len(r.locals) + 1):
                Var.map.pop(n, None)
        for insn in r.insns:
            if insn.addr in r.bbs and insn is not r.insns[0]:
                print()
            print_insn(insn, verbs)
        print()
        print()
        print()

    print()
    print()
    print()
    print('verb codes:')
    for v, ww in verbs.items():
        print(f"[{v:02x}] {' '.join(ww)}")


def splat(z, oidx):
    o = z.obj(oidx)
    for p in o.props():
        if p.len == 1:
            ooidx = int.from_bytes(p.data)
            if 1 <= ooidx <= 255:
                oo = z.obj(ooidx)
                print(hex(p.num), f"{ooidx:02x}", oo.shortname)


if __name__ == '__main__':
    fname = 'zork1-r88-s840726.z3'
    import sys

    if sys.flags.interactive:
        z = ZMech(fname)
        z.load()
        verbs = slurp_verbs(z)
    else:
        main(fname)
