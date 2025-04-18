#!/usr/bin/env python3

import copy
import itertools
from collections import defaultdict as ddict

from zmech import ZMech
from zmech.disasm import Routine, parse_routine
from zmech.structs import Imm, Var

ATTRIBUTES = {
    0x03: "LONG_DESC_SEEN",
    0x06: "ROOM?",
    0x0B: "OPEN",  # (as in (eb)[kitchen window] or bottle)
    0x1B: "BOAT",
}

# Props:
# 0x2: TODO unknown callable paddr
# 0x4: list-of-[noun-addr, call-paddr] for I guess interactables that aren't oidxs
# 0x5: list-of-oidxs of interactables (eg stairs, chimney, window)
# 0x9: TODO unknown callable paddr
# 0xb: first-encounter text?
# 0xc: point score value? for taking? see @a3f0 in [a3e0]
# 0xd: point score value? eg for finding (a3)[large emerald]
# 0xe: paddr of out-in-world description for nouns
# 0x10: list-of-adj-codes to I guess disambiguate this noun
# 0x11 callable paddr (interact specialization?):
#   0x3: print long/first-visit description
#   0x4: print short/repeat-visit description (probably)
#   0x6: perform "take" failure?
# 0x12: list-of-words, each word is a direct (z)addr to a synonym noun in the dictionary
# DIRECTIONS: len 1 => obj, len 2 => string to print instead
#   see [8aa4], seems to be the "go in X direction" routine
# 0x13: land via boat (room oidx)
# 0x14: exit (also has [loc, exit-via] oidx pairs)
# 0x15: enter (also has [loc, enter-via] oidx pairs)
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
    swaps = [
        (0x22, "enter"),
        (0x2B, "open"),
        (0x40, "give"),
        (0x6D, "ring"),
        (0x7D, "swim"),
    ]
    for code, verb in swaps:
        ww = verbs_by_code[code]
        idx = ww.index(verb)
        ww[0], ww[idx] = ww[idx], ww[0]
        verbs_by_code[code] = ww
    return verbs_by_code


def print_insn(insn, verbs_by_code):
    if insn.name == "je" and str(insn.args[0]) == '$verb_v136':
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

    notes_to_add[z.init_pc - 1].append('<start>')

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
            if prop.num in [0x4]:
                words = prop.words
                for i in range(0, len(words), 2):
                    item = z.readZ(words[i])
                    dst = words[i + 1] * 2
                    notes_to_add[dst].append(f"{obj} prop {hex(prop.num)} : {item}")

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
        r = parse_routine(z)
        if z.tell() in (0x6E4B, 0x8497):
            parse_routine(z, r=r)
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

    # check that we have routines for all expected sites
    for dst, notes in notes_to_add.items():
        if dst in routines:
            routines[dst].notes.extend(notes)
        else:
            print(f"not found: [{dst:04x}]")

    # backfill callee nargs based on callers
    for dst, nargs in call_args.items():
        r = routines[dst]
        r.args = min(nargs, len(r.locals))

    # find all insns that write to global vars
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

    # are there any routines we don't know from whence they came?
    for dst, r in routines.items():
        if isinstance(r, Routine):
            if not r.notes:
                print(f"[{dst:04x}] has no notes")

    print()
    print()
    print()
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
                Var.map[n] = f'arg'
                if r.locals[n - 1]:
                    args.append(f"{Var(n)}={r.locals[n-1]}")
                else:
                    args.append(f"{Var(n)}")
            args = ', '.join(args)
            frags.append(f"({args})")
            print(' '.join(frags))
            for n in range(r.args + 1, len(r.locals) + 1):
                Var.map[n] = f'local'
                if r.locals[n - 1]:
                    print(f"  {Var(n)} = {r.locals[n-1]}")
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
