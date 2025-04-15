#!/usr/bin/env python3

import sys
from pathlib import Path

from attrs import define, field

from zmech import ZMech, zdecode


@define
class Imm:
    value: int

    def __str__(self):
        return f"0x{self.value:x}"


@define
class Str:
    s: str

    def __str__(self):
        s = self.s.replace('"', '\\"')
        return f'"{s}"'


@define
class Var:
    idx: int

    seen = set()
    map = None

    def __attrs_post_init__(self):
        Var.seen.add(self.idx)

    def __str__(self):
        if self.map and self.idx in self.map:
            return f"${self.map[self.idx]}"
        return f"$v{self.idx}"


@define
class Insn:
    name: str = None
    args: list = field(factory=list)
    out: Var | None = None
    br_dir: bool | None = None
    br_ret: bool | None = None
    dst: int | None = None
    addr: int = 0
    end: int = 0

    def __str__(self):
        frags = [f"{self.addr:04x} : {self.name} "]
        args = ''
        if self.args:
            args = self.args[:]
            if self.name in (
                'store',
                'load',
                'inc_chk',
                'dec_chk',
                'inc',
                'dec',
                'pull',
            ):
                vidx, args = args[0], args[1:]
                if isinstance(vidx, Imm):
                    v = Var(vidx.value)
                    frags.append(f"({v})")
                elif isinstance(vidx, Var):
                    frags.append(f"(({vidx}))")
            args = ' '.join(map(str, args))
        frags.append(args)
        if self.out:
            frags.append(f"-> {self.out}")
        if self.br_dir is not None:
            word = ["or", "and"][self.br_dir]
            frags.append(word)
        if self.br_ret is not None:
            frags.append(f"ret {str(self.br_ret).lower()}")
        if self.dst:
            frags.append(f"go [{self.dst:04x}]")
        return ' '.join(frags).strip()


def parse_one(z):
    print = lambda *args, **kwargs: None
    insn = Insn(addr=z.tell())
    opcode = z.readB()
    print(f"{opcode:02x} :", end=' ')
    opclass = opcode >> 4
    if 0 <= opclass <= 0x7 or 0xC <= opclass <= 0xD:
        print('2OP', end=' ')
        opclass = opclass & 0b1110
        code = opcode & 0x1F
        table = [
            None,
            "je ?",
            "jl ?",
            "jg ?",
            "dec_chk ?",
            "inc_chk ?",
            "jin ?",
            "test ?",
            "or ->",
            "and ->",
            "test_attr ?",
            "set_attr",
            "clear_attr",
            "store",
            "insert_obj",
            "loadw ->",
            "loadb ->",
            "get_prop ->",
            "get_prop_addr ->",
            "get_next_prop ->",
            "add ->",
            "sub ->",
            "mul ->",
            "div ->",
            "mod ->",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ]
        opname = table[code]
        if not opname:
            print()
            return
        print(opname, end=' ')
        if opclass < 0x8:
            print(':', end=' ')
            # first arg
            if opclass in (0x0, 0x2):  # small constant
                c = z.readB()
                print(f"c={c:02x} ({c})", end=' ')
                insn.args.append(Imm(c))
            elif opclass in (0x4, 0x6):  # var
                vidx = z.readB()
                print(f"vidx={vidx}", end=' ')
                insn.args.append(Var(vidx))
            print(':', end=' ')
            # second arg
            if opclass in (0x0, 0x4):  # small constant
                c = z.readB()
                print(f"c={c:02x} ({c})", end=' ')
                insn.args.append(Imm(c))
            elif opclass in (0x2, 0x6):  # var
                vidx = z.readB()
                print(f"vidx={vidx}", end=' ')
                insn.args.append(Var(vidx))
        else:
            optys = z.readB()
            optys = f"{optys:08b}"
            # XXX not sure why I'm seeing more than two
            optys = [optys[:2], optys[2:4], optys[4:6], optys[6:8]]
            for opty in optys:
                if opty == '00':  # large constant
                    print(':', end=' ')
                    c = z.readW()
                    print(f"c={c:04x} ({c})", end=' ')
                    insn.args.append(Imm(c))
                elif opty == '01':  # small constant
                    print(':', end=' ')
                    c = z.readB()
                    print(f"c={c:02x} ({c})", end=' ')
                    insn.args.append(Imm(c))
                elif opty == '10':  # var
                    print(':', end=' ')
                    vidx = z.readB()
                    print(f"vidx={vidx}", end=' ')
                    insn.args.append(Var(vidx))
                elif opty == '11':  # -no arg-
                    break
    elif 0x8 <= opclass <= 0xA:
        print('1OP', end=' ')
        code = opcode & 0xF
        table = [
            "jz ?",
            "get_sibling -> ?",
            "get_child -> ?",
            "get_parent ->",
            "get_prop_len ->",
            "inc",
            "dec",
            "print_addr",
            None,
            "remove_obj",
            "print_obj",
            "ret",
            "jump",
            "print_paddr",
            "load ->",
            "not ->",
        ]
        opname = table[code]
        if not opname:
            print()
            return
        print(opname, end=' ')
        print(':', end=' ')
        if opclass == 0x8:  # large constant
            c = z.readW(signed=True)
            print(f"c={c:04x} ({c})", end=' ')
            insn.args.append(Imm(c))
        elif opclass == 0x9:  # small constant
            c = z.readB(signed=False)
            print(f"c={c:02x} ({c})", end=' ')
            insn.args.append(Imm(c))
        elif opclass == 0xA:  # var
            vidx = z.readB()
            print(f"vidx={vidx}", end=' ')
            insn.args.append(Var(vidx))
        if opname == 'jump':
            dst = z.tell() + c - 2
            insn.dst = dst
            print(f"which is [{dst:04x}]", end=' ')
    elif opclass == 0xB:
        print('0OP', end=' ')
        code = opcode & 0xF
        table = [
            "rtrue",
            "rfalse",
            "print",
            "print_ret",
            "nop",
            "save ?",
            "restore ?",
            "restart",
            "ret_popped",
            "pop",
            "quit",
            "new_line",
            "show_status",
            "verify ?",
            None,
            None,
        ]
        opname = table[code]
        if not opname:
            print()
            return
        print(opname, end=' ')
        if opname in ('print', 'print_ret'):
            print(':', end=' ')
            s = z.readZ()
            insn.args.append(Str(s))
            print(s, end=' ')
    elif 0xE <= opclass <= 0xF:
        print('VAR', end=' ')
        opclass = opclass & 0b1110
        code = opcode & 0x1F
        table = [
            "call ->",
            "storew",
            "storeb",
            "put_prop",
            "sread",
            "print_char",
            "print_num",
            "random ->",
            "push",
            "pull",
            "split_window",
            "set_window",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "output_stream",
            "input_stream",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ]
        opname = table[code]
        if not opname:
            print()
            return
        print(opname, end=' ')
        optys = z.readB()
        optys = f"{optys:08b}"
        optys = [optys[:2], optys[2:4], optys[4:6], optys[6:8]]
        for opty in optys:
            if opty == '00':  # large constant
                print(':', end=' ')
                c = z.readW()
                print(f"c={c:04x} ({c})", end=' ')
                insn.args.append(Imm(c))
            elif opty == '01':  # small constant
                print(':', end=' ')
                c = z.readB()
                print(f"c={c:02x} ({c})", end=' ')
                insn.args.append(Imm(c))
            elif opty == '10':  # var
                print(':', end=' ')
                vidx = z.readB()
                print(f"vidx={vidx}", end=' ')
                insn.args.append(Var(vidx))
            elif opty == '11':  # -no arg-
                break
        if opname == "call ->":
            rid = insn.args[0]
            if isinstance(insn.args[0], Imm):
                rid = insn.args[0].value
                # nlocals = z.readB(rid * 2)
                # dst = rid * 2 + 1 + 2 * nlocals
                dst = rid * 2
                insn.dst = dst
                print(f"/so dst is [{dst:04x}]/", end=' ')
            else:
                print(f"/?? dynamic call ??/", end=' ')
    if ' ->' in opname:
        # store target
        print(':', end=' ')
        vidx = z.readB()
        insn.out = Var(vidx)
        print(f"-> [vidx={vidx}]", end=' ')
    if ' ?' in opname:
        # jump label
        print(':', end=' ')
        lcode = z.readB()
        br_dir = lcode & 0x80  # 0 -> br if false, 1 -> br if true
        insn.br_dir = bool(br_dir)
        print('+' if br_dir else '-', end='')
        off = lcode & 0x3F
        if not (lcode & 0x40):
            off = (off << 8) | z.readB()
            if off & 0x2000:
                # 2's complement on a 14-bit number
                off -= 0x4000
        if off == 0:
            # return false from current routine
            insn.br_ret = False
            print('[false]', end=' ')
        elif off == 1:
            # return true from current routine
            insn.br_ret = True
            print('[true]', end=' ')
        else:
            dst = z.tell() + off - 2
            insn.dst = dst
            print(f"[{dst:04x}]", end=' ')
    print()
    insn.name = opname.split()[0]
    insn.end = z.tell()
    return insn


BB_END = "ret jump rtrue rfalse print_ret restore restart ret_popped quit".split()


def parse_routine(z, addr):
    insns = []
    seen = set()
    rstarts = set()
    jumps = set()
    z.seek(addr)
    while True:
        insn = parse_one(z)
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
