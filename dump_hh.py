#!/usr/bin/env python3

import copy
import re
from collections import defaultdict as ddict
from contextlib import suppress

from zmech import ZMech
from zmech.disasm import Routine, parse_routine
from zmech.structs import Imm, Var


def _tr_imm(imm):
    if isinstance(imm, Imm):
        return imm.value
    elif isinstance(imm, int):
        return imm
    return None


ATTRIBUTES = {}


def _attr(code):
    if name := ATTRIBUTES.get(_tr_imm(code)):
        return f":{name}:"
    return code


PROPERTIES = {}


def _prop(code):
    if name := PROPERTIES.get(_tr_imm(code)):
        return f":{name}:"
    return code


Var.map = {
    0: "sp",
    16: "loc",
    17: "score",
    18: "turns",
    219: "action",
    217: "direct",
    218: "indirect",
}

ACTIONS = {}


def _action(code):
    if name := ACTIONS.get(_tr_imm(code)):
        return f"[act:{name.upper().replace(' ', '_')}]"
    return code


ROUTINES = {
    0x50EE: ["random_el", "pArray"],
    0x561A: [
        "perform_action",
        "tmpAction",
        "tmpDirect",
        "tmpIndirect",
        "handled",
        "savedAction",
        "savedDirect",
        "savedIndirect",
    ],
    0x5710: [None, "pzDbgTag", "pcSomething", "bSomething"],
    0x5730: [None, "pcSomething"],
}


def _dst(dst, paddr=False):
    v = _tr_imm(dst)
    if not v:
        return dst
    if paddr:
        v *= 2
    if (info := ROUTINES.get(v)) and info[0]:
        return f"[{info[0]}]"
    return f"[{v:04x}]"


def print_insn(z, insn, block_labels=None):
    def _obj(code):
        if isinstance(n := _tr_imm(code), int) and 0 < n < 256:
            o = z.obj(n)
            return f'(0x{n:02x})["{o.shortname}"]'
        return code

    insn = copy.copy(insn)
    notes = ""

    if insn.name == "je":
        match str(insn.args[0]):
            # case '$action_v136':
            #     for i in range(1, len(insn.args)):
            #         insn.args[i] = _action(insn.args[i])
            case '$loc_v16' | '$direct_v217' | '$indirect_v218' | "$actor_v127":
                for i in range(1, len(insn.args)):
                    insn.args[i] = _obj(insn.args[i])
            case s if s.startswith('$o_'):
                for i in range(1, len(insn.args)):
                    insn.args[i] = _obj(insn.args[i])
    if insn.name in (
        "jin",
        "test_attr",
        "set_attr",
        "clear_attr",
        "get_prop",
        "get_prop_addr",
        "put_prop",
        "get_child",
        "get_sibling",
        "get_parent",
        "print_obj",
        "insert_obj",
    ):
        insn.args[0] = _obj(insn.args[0])
    if insn.name in ("jin", "insert_obj"):
        insn.args[1] = _obj(insn.args[1])
    if insn.name in ("test_attr", "set_attr", "clear_attr"):
        insn.args[1] = _attr(insn.args[1])
    if insn.name in ("get_prop", "get_prop_addr", "put_prop"):
        insn.args[1] = _prop(insn.args[1])
    if insn.name in ("call",):
        with suppress(KeyError, IndexError, AttributeError):
            rinfo = ROUTINES[insn.dst]
            for i in range(1, len(insn.args)):
                if 'Action' in rinfo[i]:
                    insn.args[i] = _action(insn.args[i])
                elif 'Direct' in rinfo[i] or 'Indirect' in rinfo[i]:
                    insn.args[i] = _obj(insn.args[i])
                elif re.match(r'pc[A-Z]', rinfo[i]):
                    insn.args[i] = _dst(insn.args[i], paddr=True)
                elif re.match(r'o[A-Z]', rinfo[i]):
                    insn.args[i] = _obj(insn.args[i])
                elif re.match(r'pz[A-Z]', rinfo[i]):
                    if p := _tr_imm(insn.args[i]):
                        p *= 2
                        s = z.readZ(p)
                        insn.args[i] = f"({p:04x})"
                        s = s.replace('"', '\"')
                        notes += f'  ; "{s}"'
        dst = _dst(insn.args[0], paddr=True)
        if dst != insn.args[0]:
            insn.args[0] = dst
            insn.dst = None
    if block_labels and insn.dst in block_labels:
        insn.dst = block_labels[insn.dst]
    print(insn.pretty() + notes)


def main(fname):
    z = ZMech(fname)
    z.load()

    routines = {}

    max_oidx = (z.obj(1)._plist - z.obj(1)._addr) // (z.obj(2)._addr - z.obj(1)._addr)

    notes_to_add = ddict(list)
    call_args = ddict(int)

    gvar_setters = ddict(list)

    notes_to_add[z.init_pc - 1].append('<start>')

    # parse all routines, by sequentially scanning through instruction memory
    z.seek(0x50EE)
    while z.tell() < 0x19F28:
        r = parse_routine(z)
        # if z.tell() in (0x710d,):
        #     parse_routine(z, r=r)
        routines[r.header] = r
        for call in r.calls:
            callhdr = call.args[0].value * 2
            calledby = _dst(r.header)
            notes_to_add[callhdr].append(f"called by {calledby}: {call.pretty()}")
            call_args[callhdr] = max(call_args[callhdr], len(call.args[1:]))
            if callhdr in (0x5472, 0x5486) and (pcCb := _tr_imm(call.args[1])):
                pcCb *= 2
                notes_to_add[pcCb].append(
                    f"ticker callback, set by {calledby}: {call.pretty()}"
                )
                call_args[pcCb] = max(call_args[pcCb], 0)
        z.seek(r.insns[-1].end)
        if z.tell() % 2 == 1:
            z.skip(1)
    with suppress(EOFError):
        while True:
            a = z.tell()
            routines[a] = z.readZ()

    # check that we have routines for all expected sites
    for dst, notes in notes_to_add.items():
        if dst in routines:
            routines[dst].notes.extend(notes)
        else:
            print(f"not found: [{dst:04x}]")

    # backfill callee nargs based on callers
    for dst, nargs in call_args.items():
        with suppress(KeyError):
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
    story_size = z.readW(0x1A) * 2
    print(f"file length: {hex(story_size)} ({hex(len(z.fp.getbuffer()))})")

    print()
    z.seek(0)

    def _spit():
        return f"{z.tell():04x} :"

    print(_spit(), z.readB(), " ; Z-machine version")
    print(_spit(), format(flags1 := z.readB(), "08b"), " ; flags 1")
    print('      ', f"status type:", "TIME" if (flags1 & 0x80 >> 1) else "SCORE")
    print('      ', f"split story:", "YES" if (flags1 & 0x80 >> 2) else "NO")
    print(_spit(), z.readW(), " ; release version")
    print(_spit(), format(z.readW(), "04x"), " ; high memory")
    print(_spit(), format(z.readW(), "04x"), " ; initial program counter")
    print(_spit(), format(z.readW(), "04x"), " ; dictionary")
    print(_spit(), format(z.readW(), "04x"), " ; object table")
    print(_spit(), format(z.readW(), "04x"), " ; global variables")
    print(_spit(), format(z.readW(), "04x"), " ; static memory")
    print(_spit(), format(z.readB(), "08b"), " ; flags 2")
    print(_spit(), format(z.readB(), "02x"))
    print(_spit(), '"' + z.read(6).decode('ascii') + '"', " ; serial number")
    print(_spit(), format(z.readW(), "04x"), " ; abbreviations table")
    print(_spit(), format(z.readW() * 2, "04x"), " ; file length")
    print(_spit(), format(z.readW(), "04x"), " ; checksum")

    mem_markers = [
        (0, 0x40, 'header'),
        (0x40, None, 'general dynamic memory'),
        (z.himem, None, 'high memory'),
        (z.globalmem, None, 'global vars'),
        (z.globalmem + 2 * 240, None, '(max extent of global vars)'),
        (z.staticmem, None, 'static mem'),
        # (0x10B16, None, '(zstrings)'),
    ]

    # dictionary
    z.seek(z.dict_start)
    start, z.dict_start = z.tell(), None
    z.load_dictionary()
    end, z.dict_start = z.tell(), start
    mem_markers.append((start, end, 'dictionary'))

    # abbrevs table
    z.seek(z.abbrev_start)
    start, z.abbrev_start = z.tell(), None
    z.load_abbrevs()
    end, z.abbrev_start = z.tell(), start
    mem_markers.append((start, end, 'abbrev table'))

    # objects and proplists
    mem_markers.append((z.object_table, None, 'object table'))
    mem_markers.append((z.object_table, z.object_table + 31 * 2, 'default props'))
    pstart = z.obj(1)._plist
    for n in range(1, 256):
        if z.obj(n)._addr >= pstart:
            o = z.obj(n - 1)
            mem_markers.append((z.obj(1)._addr, o._addr + 9, 'objects'))
            pend = (
                o._plist + 1 + 2 * z.readB(o._plist) + sum(1 + p.len for p in o.props())
            )
            mem_markers.append((pstart, pend, 'property lists'))
            break

    # potential global pointers
    for vidx in range(16, 256):
        v = z.gvar(vidx)
        if z.globalmem + 2 * (203 - 16) <= v and vidx not in {44, 45}:
            mem_markers.append((v, None, str(Var(vidx))))

    # dump completed memory layout
    print()
    print()
    print()
    print("file/memory layout")
    print()
    for addr, end, name in sorted(mem_markers, key=lambda tp: (tp[0], tp[1] or 0)):
        if end is not None:
            print(f"{addr:04x} - {end:04x} : {name}")
        else:
            print(f"{addr:04x}        : {name}")

    # misc
    print()
    print()

    print()

    # dump global variables
    print()
    print()
    print()
    for vidx in range(16, 256):
        if not z.gvar(vidx) and vidx not in Var.map and vidx not in gvar_setters:
            continue
        v = Var(vidx)
        val = z.gvar(vidx)
        print(f"{v}: {val:04x}", end='')
        if val * 2 in routines:
            if val * 2 >= 0x19F28:
                s = z.readZ(val * 2)
                s = s.replace('"', '\"')
                print(f'  ; [{val*2:04x}] "{s}"', end='')
            else:
                print(f"  ; routine? [{val*2:04x}]", end='')
        if vidx in gvar_setters:
            setters = ' '.join(f"[{insn.addr:04x}]" for insn in gvar_setters[vidx])
            print(f"  ; setters: {setters}", end='')
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
        rinfo = None
        if rstart in ROUTINES:
            rinfo = ROUTINES[rstart]
            if rinfo[0]:
                print(f"{rinfo[0]}:")
        for n in range(1, 16):
            Var.map.pop(n, None)
        if rinfo:
            for n, name in enumerate(rinfo[1:], start=1):
                if name is not None:
                    Var.map[n] = name
        if r.args is not None:
            frags = [f"{r.header:04x} :"]
            # print(f"{r.header:04x} :", r.locals[:r.args], r.locals[r.args:])
            args = []
            for n in range(1, r.args + 1):
                Var.map.setdefault(n, 'arg')
            for n in range(r.args + 1, len(r.locals) + 1):
                Var.map.setdefault(n, 'local')
            for n in range(1, r.args + 1):
                if r.locals[n - 1]:
                    args.append(f"{Var(n)}={r.locals[n-1]}")
                else:
                    args.append(f"{Var(n)}")
            args = ', '.join(args)
            frags.append(f"({args})")
            print(' '.join(frags))
            for n in range(r.args + 1, len(r.locals) + 1):
                if r.locals[n - 1]:
                    print(f"  {Var(n)} = {r.locals[n-1]}")
                elif Var.map[n] != 'local':
                    print(f"  {Var(n)}")
                else:
                    print(f"  | {Var(n)}")
        else:
            print(f"{r.header:04x} :", r.locals)
            for n in range(1, len(r.locals) + 1):
                if r.locals[n - 1]:
                    print(f"  {Var(n)} = {r.locals[n-1]}")
        loops = {}
        for insn in r.insns:
            if insn.addr in r.bbs:  # and insn is not r.insns[0]:
                print()
            if insn.addr in r.back_jumps:
                loop_counter = len(loops) + 1
                label = f".L{loop_counter}"
                loops[insn.addr] = label
                print(f"{label}:")
            print_insn(z, insn, loops)
        print()
        print()
        print()


if __name__ == '__main__':
    fname = './hitchhiker-r59-s851108.z3'
    import sys
    from contextlib import redirect_stdout
    from io import StringIO
    from pathlib import Path

    if sys.flags.interactive:
        z = ZMech(fname)
        z.load()

        def obj(oidx):
            o = z.obj(oidx)
            print(o)
            for c in o.children():
                print('  ', end='')
                print(c)
            for p in o.props():
                print('  ', end='')
                print(str(p))

    else:
        with redirect_stdout(StringIO()) as ss:
            main(fname)
        Path('hh.asm').write_text(ss.getvalue())
