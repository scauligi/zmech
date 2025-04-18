import random
import re

from .structs import Frame, Var
from .util import _s, printd


def _ret(z, val):
    frame = z.frames.pop()
    z.seek(frame.ret)
    z.set(frame.out, val)


def _br(z, insn, br_dir):
    if bool(br_dir) == bool(insn.br_dir):
        printd(f"  (taken: {insn.br_dir} == {br_dir})")
        if insn.br_ret is not None:
            _ret(z, int(insn.br_ret))
        elif insn.dst is not None:
            z.seek(insn.dst)
        else:
            raise RuntimeError(
                f"unknown dst/ret for instr {insn.name!r} at 0x{insn.addr:04x}"
            )
    else:
        printd(f"  (fallthru: {insn.br_dir} != {br_dir})")


def doInsn(z, insn):
    args = [z.eval(arg) for arg in insn.args]
    if None not in args:
        printd(f"{insn.addr:04x} : {insn.name}  {' '.join(map(hex, args))}", end='')
        if insn.out:
            printd(f"  -> {insn.out}", end='')
        if insn.br_dir is not None:
            printd(f"  br if {insn.br_dir}", end='')
        printd()
    match insn.name:
        case "nop":
            pass
        case "quit":
            z.ended = True
            pass
        case "save" | "restore" | "restart":
            raise NotImplementedError(insn.name)
        case "add":
            z.set(insn.out, _s(args[0]) + _s(args[1]))
        case "sub":
            z.set(insn.out, _s(args[0]) - _s(args[1]))
        case "mul":
            z.set(insn.out, _s(args[0]) * _s(args[1]))
        case "div" | "mod":
            a, b = _s(args[0]), _s(args[1])
            d, m = divmod(a, b)
            if (a < 0) != (b < 0):
                d += 1
                m -= b
            z.set(insn.out, d if insn.name == "div" else m)
        case "and":
            z.set(insn.out, args[0] & args[1])
        case "or":
            z.set(insn.out, args[0] | args[1])
        case "not":
            z.set(insn.out, ~args[0])
        case "inc" | "inc_chk":
            v = Var(args[0])
            nv = z.eval(v, _indirect=True) + 1
            z.set(v, nv, _indirect=True)
            if insn.name == "inc_chk":
                _br(z, insn, _s(nv) > _s(args[1]))
        case "dec" | "dec_chk":
            v = Var(args[0])
            nv = z.eval(v, _indirect=True) - 1
            z.set(v, nv, _indirect=True)
            if insn.name == "dec_chk":
                _br(z, insn, _s(nv) < _s(args[1]))
        case "jump":
            z.seek(insn.dst)
        case "jz":
            _br(z, insn, args[0] == 0)
        case "je":
            a0 = args[0]
            _br(z, insn, any(a0 == a for a in args[1:]))
        case "jl":
            assert len(args) == 2
            _br(z, insn, _s(args[0]) < _s(args[1]))
        case "jg":
            assert len(args) == 2
            _br(z, insn, _s(args[0]) > _s(args[1]))
        case "test":
            assert len(args) == 2
            _br(z, insn, args[0] & args[1] == args[1])
        case "call":
            ret = z.tell()
            dst = 2 * args[0]
            if dst == 0:
                z.set(insn.out, 0)
            else:
                z.seek(dst)
                nlocals = z.readB()
                lvars = [z.readW() for _ in range(nlocals)]
                args = args[1:]  # since the first arg is the call target
                assert len(args) <= len(lvars), f"{len(insn.args)=} {len(lvars)=}"
                lvars[: len(args)] = args
                z.frames.append(Frame(ret, lvars, insn.out))
        case "ret":
            _ret(z, args[0])
        case "rtrue":
            _ret(z, 1)
        case "rfalse":
            _ret(z, 0)
        case "ret_popped":
            _ret(z, z.stack.pop())
        case "load":
            z.set(insn.out, z.eval(Var(args[0]), _indirect=True))
        case "store":
            z.set(args[0], args[1], _indirect=True)
        case "push":
            z.stack.append(args[0])
        case "pull":
            z.set(args[0], z.stack.pop(), _indirect=True)
        case "pop":
            z.stack.pop()
        case "loadb":
            val = z.readB((args[0], _s(args[1])))
            z.set(insn.out, val)
        case "loadw":
            val = z.readW((args[0], _s(args[1])))
            z.set(insn.out, val)
        case "storeb":
            z.writeB((args[0], _s(args[1])), args[2])
        case "storew":
            z.writeW((args[0], _s(args[1])), args[2])
        case "random":
            n = args[0]
            r = 0
            if n < 0:
                random.seed(n)
            elif n == 0:
                random.seed()
            else:
                r = random.randint(1, args[0])
            z.set(insn.out, r)
        case "verify" | "piracy":
            _br(z, insn, True)
        case "print":
            print(insn.args[0].s, end='')
        case "print_ret":
            print(insn.args[0].s)
            _ret(z, 1)
        case "print_char":
            print(chr(args[0]), end='')
        case "print_num":
            print(_s(args[0]), end='')
        case "print_addr":
            print(z.readZ(args[0]), end='')
        case "print_paddr":
            print(z.readZ(args[0] * 2), end='')
        case "print_obj":
            o = z.obj(args[0])
            print(o.shortname, end='')
        case "new_line":
            print()
        case "test_attr":
            if args[0] == 0:
                _br(z, insn, False)
            else:
                o = z.obj(args[0])
                _br(z, insn, o.test_attr(args[1]))
        case "set_attr":
            o = z.obj(args[0])
            o.set_attr(args[1])
        case "clear_attr":
            o = z.obj(args[0])
            o.clear_attr(args[1])
        case "get_prop":
            o = z.obj(args[0])
            n = args[1]
            if prop := o.prop(n):
                assert prop.len <= 2
                val = prop.value
            else:
                val = z.default_props[n]
            z.set(insn.out, val)
        case "get_prop_addr":
            o = z.obj(args[0])
            n = args[1]
            if prop := o.prop(n):
                z.set(insn.out, prop.addr)
            else:
                z.set(insn.out, 0)
        case "get_prop_len":
            if args[0] == 0:
                z.set(insn.out, 0)
            else:
                szbyte = z.readB(args[0] - 1)
                assert szbyte
                nbytes = (szbyte >> 5) + 1
                z.set(insn.out, nbytes)
        case "get_next_prop":
            o = z.obj(args[0])
            n = args[1]
            res = 0
            if n == 0:
                res = next(o.props()).num
            else:
                for p in o.props():
                    if p.num < n:
                        res = p.num
                        break
            z.set(insn.out, res)
        case "put_prop":
            o = z.obj(args[0])
            n = args[1]
            if p := o.prop(n):
                if p.len == 1:
                    z.writeB(p.addr, args[2] & 0xFF)
                elif p.len == 2:
                    z.writeW(p.addr, args[2])
                else:
                    raise Exception(
                        f"prop {hex(n)} for obj {hex(args[0])} has bad length"
                    )
            else:
                raise RuntimeError(
                    f"prop {hex(n)} does not exist for obj {hex(args[0])}"
                )
        case "get_parent":
            o = z.obj(args[0])
            z.set(insn.out, o._parent)
        case "jin":
            if not args[0]:
                _br(z, insn, False)
            else:
                o = z.obj(args[0])
                _br(z, insn, o._parent == args[1])
        case "get_child":
            o = z.obj(args[0])
            z.set(insn.out, o._child)
            _br(z, insn, o._child)
        case "get_sibling":
            o = z.obj(args[0])
            z.set(insn.out, o._sibling)
            _br(z, insn, o._sibling)
        case "insert_obj":
            o = z.obj(args[0])
            d = z.obj(args[1])
            if o.parent:
                p = o.parent
                if p._child == o.idx:
                    p.child = o.sibling
                else:
                    s = p.child
                    while s.sibling:
                        if s._sibling == o.idx:
                            s.sibling = o.sibling
                            break
                        s = s.sibling
            o.parent = d.idx
            o.sibling = d.child
            d.child = o.idx
        case "remove_obj":
            o = z.obj(args[0])
            if o.parent:
                p = o.parent
                if p._child == o.idx:
                    p.child = o.sibling
                else:
                    s = p.child
                    while s.sibling:
                        if s._sibling == o.idx:
                            s.sibling = o.sibling
                            break
                        s = s.sibling
            o.parent = 0
            o.sibling = 0
        case "show_status":
            z.show_status()
        case "sread":
            bufp = args[0]
            parsep = args[1]

            maxchars = z.readB(bufp)
            z.show_status()
            try:
                s = input().lower().encode()[:maxchars] + b'\0'
            except EOFError:
                s = b"\0"
            with z.seek(bufp + 1):
                z.fp.write(s)

            maxwords = z.readB(parsep)

            seps = ''.join(z.seps)
            seps = rf"([{seps}]|\s+)"
            words = s[:-1].decode()
            words = re.split(seps, words)
            with z.seek(parsep + 2):
                nwords = 0
                tidx = 1
                for word in words:
                    if not word.strip():
                        tidx += len(word)
                        continue
                    addr = z.dict.get(word[:6], 0)
                    z.writeW(None, addr)
                    z.writeB(None, len(word))
                    z.writeB(None, tidx)
                    tidx += len(word)
                    nwords += 1
                    if nwords == maxwords:
                        break
            z.writeB(parsep + 1, nwords)
        case _:
            raise RuntimeError(f"unknown instr")
