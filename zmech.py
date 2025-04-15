import contextlib
import io
import random
from pathlib import Path

from attrs import define, field

_DEBUG = True


def printd(*args, **kwargs):
    if _DEBUG:
        print(*args, **kwargs)


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

    map = None

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


@define
class Frame:
    ret: int
    locals: list[int]
    out: Var


@define
class Prop:
    num: int
    len: int
    addr: int
    data: bytes = None


@define
class Obj:
    _z: "ZMech"
    idx: int

    @property
    def _addr(self):
        return self._z.object_table + 31 * 2 + 9 * (self.idx - 1)

    @property
    def _attrs(self):
        return int.from_bytes(self._z.read(4, self._addr), 'big')

    @property
    def attrs(self):
        aa = self._attrs
        attrs = set()
        for n in range(8 * 4):
            if aa & (0x80000000 >> n):
                attrs.add(n)
        return frozenset(attrs)

    def test_attr(self, a):
        aa = self._attrs
        bit = 0x80000000 >> a
        return bool(aa & bit)

    def set_attr(self, a):
        aa = self._attrs
        bit = 0x80000000 >> a
        aa |= bit
        with self._z.seek(self._addr):
            self._z.fp.write(int.to_bytes(aa, 4, 'big'))

    def clear_attr(self, a):
        aa = self._attrs
        bit = 0x80000000 >> a
        aa = (aa | bit) ^ bit
        with self._z.seek(self._addr):
            self._z.fp.write(int.to_bytes(aa, 4, 'big'))

    @property
    def parent(self):
        return self._z.readB(self._addr + 4)

    @parent.setter
    def parent(self, val):
        self._z.writeB(self._addr + 4, val)

    @property
    def sibling(self):
        return self._z.readB(self._addr + 4 + 1)

    @sibling.setter
    def sibling(self, val):
        self._z.writeB(self._addr + 4 + 1, val)

    @property
    def child(self):
        return self._z.readB(self._addr + 4 + 2)

    @child.setter
    def child(self, val):
        self._z.writeB(self._addr + 4 + 2, val)

    @property
    def _plist(self):
        return self._z.readW(self._addr + 4 + 3)

    @property
    def shortname(self):
        with self._z.seek(self._plist):
            n = self._z.readB()
            return self._z.readZ(max=n)

    @property
    def props(self):
        plist = self._plist
        n = self._z.readB(plist)
        cur = plist + 1 + 2 * n
        while True:
            szbyte = self._z.readB(cur)
            if not szbyte:
                break
            propnum = szbyte & 0x1F
            nbytes = (szbyte >> 5) + 1
            yield Prop(propnum, nbytes, cur + 1, self._z.read(nbytes, cur + 1))
            cur += 1 + nbytes


def _s(n):
    n = _u(n)
    if n >= 0x8000:
        n -= 0x10000
    return n


def _u(n):
    return n % 0x10000


def zsplit(zwords):
    if isinstance(zwords, bytes):
        assert len(zwords) % 2 == 0
        zwords = [int.from_bytes(zwords[i : i + 2]) for i in range(0, len(zwords), 2)]
    for zword in zwords:
        zword = format(zword, "016b")
        end, *zcodes = map(
            lambda b: int(b, 2), [zword[0], zword[1:6], zword[6:11], zword[11:16]]
        )
        yield (end, zcodes)


A2 = " \n0123456789.,!?_#'\"/\\-:()"


def zdecode(zwords, abbrevs=None):
    if isinstance(zwords, bytes):
        assert len(zwords) % 2 == 0
        zwords = [int.from_bytes(zwords[i : i + 2]) for i in range(0, len(zwords), 2)]
    s = []
    shift = 0
    abbrev_idx = None
    tenbit = None
    end = 0
    for zword in zwords:
        zword = format(zword, "016b")
        end, *zcodes = map(
            lambda b: int(b, 2), [zword[0], zword[1:6], zword[6:11], zword[11:16]]
        )
        for zcode in zcodes:
            if tenbit is not None:
                tenbit.append(zcode)
                if len(tenbit) == 2:
                    zscii = (tenbit[0] << 5) | tenbit[1]
                    s.append(chr(zscii))  # technically not accurate but eh
                    tenbit = None
            elif abbrev_idx is not None:
                idx = 32 * abbrev_idx + zcode
                if abbrevs and idx < len(abbrevs):
                    s.append(abbrevs[idx])
                else:
                    s.append(f"<abbrev:{idx}>")
                abbrev_idx = None
            elif zcode == 0:
                s.append(' ')
            elif 1 <= zcode <= 3:
                # abbrev lookup
                abbrev_idx = zcode - 1
            elif zcode == 4:
                shift = 1
            elif zcode == 5:
                shift = 2
            elif 6 <= zcode < 0x20:
                idx = zcode - 6
                if shift == 0:
                    s.append(chr(idx + ord('a')))
                elif shift == 1:
                    s.append(chr(idx + ord('A')))
                    shift = 0
                elif shift == 2:
                    if zcode == 6:
                        tenbit = []
                    else:
                        s.append(A2[idx])
                    shift = 0
            else:
                raise Exception(f"Uh oh! Got unknown code {zcode} ({shift = })")
        if end:
            break
    if not end:
        s.append('<>')
    return ''.join(s)


class ZMech:
    def __init__(self, fname):
        self.fname = fname
        data = Path(fname).read_bytes()
        self.fp = io.BytesIO(data)
        self._loaded = False

        self.himem = 0
        self.staticmem = 0
        self.globalmem = 0
        self.init_pc = 0

        self.dict = None
        self.abbrevs = None
        self.globals = None
        self.object_table = None

        self.default_props = None

        self.frames = []
        self.stack = []
        self.ended = False

    def load(self):
        self.himem = self.readW(0x04)
        self.init_pc = self.readW(0x06)
        # self.load_dictionary()
        self.object_table = self.readW(0x0A)
        self.globalmem = self.readW(0x0C)
        self.staticmem = self.readW(0x0E)

        self.load_abbrevs()  # 0x18
        with self.seek(self.object_table):
            self.default_props = {}
            for n in range(1, 32):
                self.default_props[n] = self.readW()

        self.frames = []
        self.stack = [0]

        self.seek(self.init_pc)
        self.ended = False

        self._loaded = True

    def close(self):
        self.fp.close()

    def __enter__(self):
        if not self._loaded:
            self.load()
        return self

    def __exit__(self, ty, val, tb):
        self.close()

    def tell(self):
        return self.fp.tell()

    @contextlib.contextmanager
    def _returner(self, saved):
        yield
        self.seek(saved)

    def seek(self, addr):
        """If you use this as a context manager, it'll pop you back to where you were before"""
        saved = self.tell()
        self.fp.seek(addr, 0)
        return self._returner(saved)

    def skip(self, n):
        self.fp.seek(n, 1)

    @staticmethod
    def to_int(b, signed=False):
        return int.from_bytes(b, byteorder='big', signed=signed)

    def read(self, sz, addr=None, signed=None):
        if addr is not None:
            saved = self.tell()
            self.seek(addr)
        res = self.fp.read(sz)
        if not res:
            raise EOFError()
        if signed is not None:
            res = self.to_int(res, signed=signed)
        if addr is not None:
            self.seek(saved)
        return res

    def dump(self, addr):
        print(f"{addr:04x} ", self.read(16, addr).hex(' '))

    def readB(self, addr=None, signed=False):
        if isinstance(addr, (tuple, list)) and len(addr) == 2:
            addr = addr[0] + addr[1]
        return self.read(1, addr=addr, signed=signed)

    def readW(self, addr=None, signed=False):
        if isinstance(addr, (tuple, list)) and len(addr) == 2:
            addr = addr[0] + 2 * addr[1]
        return self.read(2, addr=addr, signed=signed)

    def writeB(self, addr, val):
        if isinstance(addr, (tuple, list)) and len(addr) == 2:
            addr = addr[0] + addr[1]
        b = val.to_bytes(1, byteorder='big', signed=(val < 0))
        with self.seek(addr):
            self.fp.write(b)

    def writeW(self, addr, val):
        if isinstance(addr, (tuple, list)) and len(addr) == 2:
            addr = addr[0] + 2 * addr[1]
        b = val.to_bytes(2, byteorder='big', signed=(val < 0))
        with self.seek(addr):
            self.fp.write(b)

    def _yieldW(self, max=None):
        if max is not None:
            for _ in range(max):
                yield self.readW()
        else:
            while True:
                yield self.readW()

    def readZ(self, addr=None, max=None, use_abbrevs=True):
        if addr is not None:
            saved = self.tell()
            self.seek(addr)
        res = zdecode(
            self._yieldW(max=max), abbrevs=(self.abbrevs if use_abbrevs else None)
        )
        if addr is not None:
            self.seek(saved)
        return res

    def gvar(self, vidx):
        "NOTE: this uses the var number (index + 16), not the actual index of the global itself"
        assert 16 <= vidx < 256
        return self.readW(self.globalmem + 2 * (vidx - 16))

    def obj(self, oidx):
        assert 0 < oidx < 256
        return Obj(self, oidx)

    def load_abbrevs(self):
        self.abbrevs = []
        abbrev_start = self.readW(0x18)
        with self.seek(abbrev_start):
            for _ in range(32 * 3):
                addr = self.readW()
                self.abbrevs.append(self.readZ(addr * 2, use_abbrevs=False))

    def readInsn(self, addr=None):
        if addr is not None:
            saved = self.tell()
            self.seek(addr)
        try:
            insn = Insn(addr=self.tell())
            opcode = self.readB()
            opclass = opcode >> 4
            if 0 <= opclass <= 0x7 or 0xC <= opclass <= 0xD:
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
                    return
                if opclass < 0x8:
                    # first arg
                    if opclass in (0x0, 0x2):  # small constant
                        c = self.readB()
                        insn.args.append(Imm(c))
                    elif opclass in (0x4, 0x6):  # var
                        vidx = self.readB()
                        insn.args.append(Var(vidx))
                    # second arg
                    if opclass in (0x0, 0x4):  # small constant
                        c = self.readB()
                        insn.args.append(Imm(c))
                    elif opclass in (0x2, 0x6):  # var
                        vidx = self.readB()
                        insn.args.append(Var(vidx))
                else:
                    optys = self.readB()
                    optys = f"{optys:08b}"
                    # XXX not sure why I'm seeing more than two
                    optys = [optys[:2], optys[2:4], optys[4:6], optys[6:8]]
                    for opty in optys:
                        if opty == '00':  # large constant
                            c = self.readW()
                            insn.args.append(Imm(c))
                        elif opty == '01':  # small constant
                            c = self.readB()
                            insn.args.append(Imm(c))
                        elif opty == '10':  # var
                            vidx = self.readB()
                            insn.args.append(Var(vidx))
                        elif opty == '11':  # -no arg-
                            break
            elif 0x8 <= opclass <= 0xA:
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
                    return
                if opclass == 0x8:  # large constant
                    c = self.readW(signed=True)
                    insn.args.append(Imm(c))
                elif opclass == 0x9:  # small constant
                    c = self.readB(signed=False)
                    insn.args.append(Imm(c))
                elif opclass == 0xA:  # var
                    vidx = self.readB()
                    insn.args.append(Var(vidx))
                if opname == 'jump':
                    dst = self.tell() + c - 2
                    insn.dst = dst
            elif opclass == 0xB:
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
                    return
                if opname in ('print', 'print_ret'):
                    s = self.readZ()
                    insn.args.append(Str(s))
            elif 0xE <= opclass <= 0xF:
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
                    return
                optys = self.readB()
                optys = f"{optys:08b}"
                optys = [optys[:2], optys[2:4], optys[4:6], optys[6:8]]
                for opty in optys:
                    if opty == '00':  # large constant
                        c = self.readW()
                        insn.args.append(Imm(c))
                    elif opty == '01':  # small constant
                        c = self.readB()
                        insn.args.append(Imm(c))
                    elif opty == '10':  # var
                        vidx = self.readB()
                        insn.args.append(Var(vidx))
                    elif opty == '11':  # -no arg-
                        break
                if opname == "call ->":
                    rid = insn.args[0]
                    if isinstance(insn.args[0], Imm):
                        rid = insn.args[0].value
                        # nlocals = self.readB(rid * 2)
                        # dst = rid * 2 + 1 + 2 * nlocals
                        dst = rid * 2
                        insn.dst = dst
            if ' ->' in opname:
                # store target
                vidx = self.readB()
                insn.out = Var(vidx)
            if ' ?' in opname:
                # jump label
                lcode = self.readB()
                br_dir = lcode & 0x80  # 0 -> br if false, 1 -> br if true
                insn.br_dir = bool(br_dir)
                off = lcode & 0x3F
                if not (lcode & 0x40):
                    off = (off << 8) | self.readB()
                    if off & 0x2000:
                        # 2's complement on a 14-bit number
                        off -= 0x4000
                if off == 0:
                    # return false from current routine
                    insn.br_ret = False
                elif off == 1:
                    # return true from current routine
                    insn.br_ret = True
                else:
                    dst = self.tell() + off - 2
                    insn.dst = dst
            insn.name = opname.split()[0]
            insn.end = self.tell()
            return insn
        finally:
            if addr is not None:
                self.seek(saved)

    def eval(self, arg, _indirect=False):
        match arg:
            case Imm(n):
                return n
            case Var(idx) if idx == 0:
                if _indirect:
                    return self.stack[-1]
                else:
                    return self.stack.pop()
            case Var(idx) if idx < 16:
                return self.frames[-1].locals[idx - 1]
            case Var(idx):
                return self.gvar(idx)

    def set(self, vidx, val, _indirect=False):
        # if val != _u(val):
        #     print(hex(self.tell()), f"SET  {vidx}  {val=}  {_u(val)=}")
        if isinstance(vidx, Var):
            vidx = vidx.idx
        val = _u(val)
        printd(f"  $v{vidx} <- {hex(val)}")
        if vidx == 0:
            if _indirect:
                self.stack[-1] = val
            else:
                self.stack.append(val)
        elif vidx < 16:
            self.frames[-1].locals[vidx - 1] = val
        else:
            return self.writeW((self.globalmem, vidx - 16), val)

    def _ret(self, val):
        frame = self.frames.pop()
        self.seek(frame.ret)
        self.set(frame.out, val)

    def _br(self, insn, br_dir):
        if bool(br_dir) == bool(insn.br_dir):
            printd(f"  (taken: {insn.br_dir} == {br_dir})")
            if insn.br_ret is not None:
                self._ret(int(insn.br_ret))
            elif insn.dst is not None:
                self.seek(insn.dst)
            else:
                raise RuntimeError(
                    f"unknown dst/ret for instr {insn.name!r} at 0x{insn.addr:04x}"
                )
        else:
            printd(f"  (fallthru: {insn.br_dir} != {br_dir})")

    def step(self):
        try:
            insn = self.readInsn()
            assert insn, "insn is None???"
            args = [self.eval(arg) for arg in insn.args]
            if None not in args:
                printd(
                    f"{insn.addr:04x} : {insn.name}  {' '.join(map(hex, args))}", end=''
                )
                if insn.out:
                    printd(f"  -> {insn.out}", end='')
                if insn.br_dir is not None:
                    printd(f"  br if {insn.br_dir}", end='')
                printd()
            match insn.name:
                case "quit":
                    self.ended = True
                    pass
                case "add":
                    self.set(insn.out, _s(args[0]) + _s(args[1]))
                case "sub":
                    self.set(insn.out, _s(args[0]) - _s(args[1]))
                case "mul":
                    self.set(insn.out, _s(args[0]) * _s(args[1]))
                case "div" | "mod":
                    a, b = _s(args[0]), _s(args[1])
                    d, m = divmod(a, b)
                    if (a < 0) != (b < 0):
                        d += 1
                        m -= b
                    self.set(insn.out, d if insn.name == "div" else m)
                case "and":
                    self.set(insn.out, args[0] & args[1])
                case "or":
                    self.set(insn.out, args[0] | args[1])
                case "not":
                    self.set(insn.out, ~args[0])
                case "inc" | "inc_chk":
                    v = Var(args[0])
                    nv = self.eval(v, _indirect=True) + 1
                    self.set(v, nv, _indirect=True)
                    if insn.name == "inc_chk":
                        self._br(insn, _s(nv) > _s(args[1]))
                case "dec" | "dec_chk":
                    v = Var(args[0])
                    nv = self.eval(v, _indirect=True) - 1
                    self.set(v, nv, _indirect=True)
                    if insn.name == "dec_chk":
                        self._br(insn, _s(nv) < _s(args[1]))
                case "jump":
                    self.seek(insn.dst)
                case "jz":
                    self._br(insn, args[0] == 0)
                case "je":
                    a0 = args[0]
                    self._br(insn, any(a0 == a for a in args[1:]))
                case "jl":
                    assert len(args) == 2
                    self._br(insn, _s(args[0]) < _s(args[1]))
                case "jg":
                    assert len(args) == 2
                    self._br(insn, _s(args[0]) > _s(args[1]))
                case "test":
                    assert len(args) == 2
                    self._br(insn, args[0] & args[1] == args[1])
                case "call":
                    ret = self.tell()
                    dst = 2 * args[0]
                    self.seek(dst)
                    nlocals = self.readB()
                    lvars = [self.readW() for _ in range(nlocals)]
                    args = args[1:]  # since the first arg is the call target
                    assert len(args) <= len(lvars), f"{len(insn.args)=} {len(lvars)=}"
                    lvars[: len(args)] = args
                    self.frames.append(Frame(ret, lvars, insn.out))
                case "ret":
                    self._ret(args[0])
                case "rtrue":
                    self._ret(1)
                case "rfalse":
                    self._ret(0)
                case "ret_popped":
                    self._ret(self.stack.pop())
                case "load":
                    self.set(insn.out, self.eval(Var(args[0]), _indirect=True))
                case "store":
                    self.set(args[0], args[1], _indirect=True)
                case "push":
                    self.stack.append(args[0])
                case "pull":
                    self.set(args[0], self.stack.pop(), _indirect=True)
                case "pop":
                    self.stack.pop()
                case "loadb":
                    val = self.readB((args[0], _s(args[1])))
                    self.set(insn.out, val)
                case "loadw":
                    val = self.readW((args[0], _s(args[1])))
                    self.set(insn.out, val)
                case "storeb":
                    self.writeB((args[0], _s(args[1])), args[2])
                case "storew":
                    self.writeW((args[0], _s(args[1])), args[2])
                case "random":
                    n = args[0]
                    r = 0
                    if n < 0:
                        random.seed(n)
                    elif n == 0:
                        random.seed()
                    else:
                        r = random.randint(1, args[0])
                    self.set(insn.out, r)
                case "verify" | "piracy":
                    self._br(insn, True)
                case "print":
                    print(insn.args[0].s, end='')
                case "print_ret":
                    print(insn.args[0].s)
                    self._ret(1)
                case "print_char":
                    print(chr(args[0]), end='')
                case "print_num":
                    print(_s(args[0]), end='')
                case "print_addr":
                    print(self.readZ(args[0]), end='')
                case "print_paddr":
                    print(self.readZ(args[0] * 2), end='')
                case "print_obj":
                    o = self.obj(args[0])
                    print(o.shortname, end='')
                case "new_line":
                    print()
                case "test_attr":
                    o = self.obj(args[0])
                    self._br(insn, o.test_attr(args[1]))
                case "set_attr":
                    o = self.obj(args[0])
                    o.set_attr(args[1])
                case "clear_attr":
                    o = self.obj(args[0])
                    o.clear_attr(args[1])
                case "get_prop":
                    o = self.obj(args[0])
                    n = args[1]
                    for prop in o.props:
                        if prop.num == n:
                            assert prop.len <= 2
                            val = int.from_bytes(prop.data)
                            break
                    else:
                        val = self.default_props[n]
                    self.set(insn.out, val)
                case "get_prop_addr":
                    o = self.obj(args[0])
                    n = args[1]
                    for prop in o.props:
                        if prop.num == n:
                            self.set(insn.out, prop.addr)
                            break
                    else:
                        self.set(insn.out, 0)
                case "get_prop_len":
                    if args[0] == 0:
                        self.set(insn.out, 0)
                    else:
                        szbyte = self.readB(args[0] - 1)
                        assert szbyte
                        nbytes = (szbyte >> 5) + 1
                        self.set(insn.out, nbytes)
                case "get_next_prop":
                    o = self.obj(args[0])
                    n = args[1]
                    res = 0
                    if n == 0:
                        res = next(o.props).num
                    else:
                        for p in o.props:
                            if p.num < n:
                                res = p.num
                                break
                    self.set(insn.out, res)
                case "put_prop":
                    o = self.obj(args[0])
                    n = args[1]
                    for p in o.props:
                        if p.num == n:
                            if p.len == 1:
                                self.writeB(p.addr, args[2] & 0xFF)
                            elif p.len == 2:
                                self.writeW(p.addr, args[2])
                            else:
                                raise Exception(
                                    f"prop {hex(n)} for obj {hex(args[0])} has bad length"
                                )
                            break
                    else:
                        raise RuntimeError(
                            f"prop {hex(n)} does not exist for obj {hex(args[0])}"
                        )
                case "get_parent":
                    o = self.obj(args[0])
                    self.set(insn.out, o.parent)
                case "jin":
                    o = self.obj(args[0])
                    p = self.obj(args[1])
                    self._br(insn, o.parent == p.idx)
                case "get_child":
                    o = self.obj(args[0])
                    self.set(insn.out, o.child)
                    self._br(insn, o.child)
                case "get_sibling":
                    o = self.obj(args[0])
                    self.set(insn.out, o.sibling)
                    self._br(insn, o.sibling)
                case "insert_obj":
                    o = self.obj(args[0])
                    d = self.obj(args[1])
                    if o.parent:
                        p = self.obj(o.parent)
                        if p.child == o.idx:
                            p.child = o.sibling
                        else:
                            s = self.obj(p.child)
                            while s.sibling:
                                if s.sibling == o.idx:
                                    s.sibling = o.sibling
                                    break
                                s = self.obj(s.sibling)
                    o.parent = d.idx
                    o.sibling = d.child
                    d.child = o.idx
                case "remove_obj":
                    o = self.obj(args[0])
                    if o.parent:
                        p = self.obj(o.parent)
                        if p.child == o.idx:
                            p.child = o.sibling
                        else:
                            s = self.obj(p.child)
                            while s.sibling:
                                if s.sibling == o.idx:
                                    s.sibling = o.sibling
                                    break
                                s = self.obj(s.sibling)
                    o.parent = 0
                    o.sibling = 0
                case "sread":
                    s = input()
                    raise NotImplementedError("actual parsing")
                case _:
                    raise RuntimeError(f"unknown instr")
        except Exception as e:
            frag = f"while executing {insn.name!r} at 0x{insn.addr:04x}"
            if e.args:
                # e.args = (str(e.args[0]) + frag, *e.args[1:])
                e.args = (*e.args, frag)
            else:
                e.args = (frag,)
            raise


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        z = ZMech(sys.argv[1])
        z.load()
