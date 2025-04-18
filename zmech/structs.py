from attrs import define, field

from .util import from_bytes, to_bytes


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

    map = {}

    def __str__(self):
        if self.idx in self.map:
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

    def pretty(self):
        frags = [f"{self.addr:04x} :"]
        args = []
        name = self.name
        br_dir = self.br_dir
        out = self.out
        dst = self.dst
        if self.args:
            args = self.args[:]
            if name in (
                'store',
                'load',
                'inc_chk',
                'dec_chk',
                'inc',
                'dec',
                'pull',
            ):
                vidx = args[0]
                if isinstance(vidx, Imm):
                    v = Var(vidx.value)
                    args[0] = f"{v}"
                elif isinstance(vidx, Var):
                    args[0] = f"({vidx})"
                if name == 'pull':
                    out = args[0]
                    args = args[1:]
                elif name.startswith('inc'):
                    args[0] = "++" + args[0]
                    if name.endswith('_chk'):
                        name = "jg"
                elif name.startswith('dec'):
                    args[0] = "--" + args[0]
                    if name.endswith('_chk'):
                        name = "jl"
            args = list(map(str, args))
        if name in ("loadb", "loadw", "storeb", "storew"):
            args[0] = f"{args[0]}[{args[1]}]"
            args[1:] = args[2:]
        if name.startswith('store'):
            args = [args[0], '=', *args[1:]]
        if name == "je":
            frags.append(f"if {args[0]}")
            frags.append("==" if self.br_dir else "<>")
            br_dir = True
            frags.append(' '.join(args[1:]))
        elif name == "jz":
            frags.append(f"if {args[0]}")
            frags.append("==" if self.br_dir else "<>")
            br_dir = True
            frags.append("0")
        elif name == "jl":
            frags.append(f"if {args[0]}")
            frags.append("<" if self.br_dir else ">=")
            br_dir = True
            frags.append(' '.join(args[1:]))
        elif name == "jg":
            frags.append(f"if {args[0]}")
            frags.append(">" if self.br_dir else "<=")
            br_dir = True
            frags.append(' '.join(args[1:]))
        elif name in ("call", "jump"):
            if args[0].startswith("0x"):
                args[0] = f"[{dst:04x}]"
                dst = None
            frags.append(f"{name} {args[0]} ")
            frags.append(' '.join(args[1:]) if args[1:] else '')
        else:
            frags.append(f"{name} ")
            frags.append(' '.join(args) if args else '')
        if out:
            frags.append(f"-> {out}")
        if br_dir is not None:
            word = ["else", "then"][br_dir]
            frags.append(word)
        if self.br_ret is not None:
            frags.append(f"ret {str(self.br_ret).lower()}")
        if dst:
            frags.append(f"go [{dst:04x}]")
        return ' '.join(frags).strip()


@define
class Frame:
    locals: list[int]
    ret: int
    out: Var
    stack: list[int] = field(factory=list)


@define
class Prop:
    num: int
    len: int
    addr: int
    data: bytes = None

    @property
    def value(self):
        return from_bytes(self.data)

    @property
    def paddr(self):
        if self.len == 2:
            return self.value * 2


@define
class Obj:
    _z: "ZMech"
    idx: int

    @property
    def _addr(self):
        return self._z.object_table + 31 * 2 + 9 * (self.idx - 1)

    @property
    def _attrs(self):
        return self._z.read(4, self._addr, signed=False)

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
            self._z.fp.write(to_bytes(aa, 4))

    def clear_attr(self, a):
        aa = self._attrs
        bit = 0x80000000 >> a
        aa = (aa | bit) ^ bit
        with self._z.seek(self._addr):
            self._z.fp.write(to_bytes(aa, 4))

    @property
    def _parent(self):
        return self._z.readB(self._addr + 4)

    @property
    def parent(self):
        if self._parent:
            return self._z.obj(self._parent)

    @parent.setter
    def parent(self, val):
        if val is None:
            val = 0
        elif isinstance(val, Obj):
            val = val.idx
        self._z.writeB(self._addr + 4, val)

    @property
    def _sibling(self):
        return self._z.readB(self._addr + 4 + 1)

    @property
    def sibling(self):
        if self._sibling:
            return self._z.obj(self._sibling)

    @sibling.setter
    def sibling(self, val):
        if val is None:
            val = 0
        elif isinstance(val, Obj):
            val = val.idx
        self._z.writeB(self._addr + 4 + 1, val)

    @property
    def _child(self):
        return self._z.readB(self._addr + 4 + 2)

    @property
    def child(self):
        if self._child:
            return self._z.obj(self._child)

    @child.setter
    def child(self, val):
        if val is None:
            val = 0
        elif isinstance(val, Obj):
            val = val.idx
        self._z.writeB(self._addr + 4 + 2, val)

    def children(self):
        cur = self.child
        while cur:
            yield cur
            cur = cur.sibling

    @property
    def _plist(self):
        return self._z.readW(self._addr + 4 + 3)

    @property
    def shortname(self):
        with self._z.seek(self._plist):
            n = self._z.readB()
            return self._z.readZ(max=n)

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

    def prop(self, num):
        for prop in self.props():
            if prop.num == num:
                return prop

    def __str__(self):
        return f"({self.idx:02x})[{self.shortname}]"

    def __rich_repr__(self):
        yield self.idx
        yield self.shortname
        yield 'parent', str(self.parent) if self._parent else None
        # yield 'sibling', str(self.sibling) if self._sibling else None
        # yield 'child', str(self.child) if self._child else None
        yield 'children', [len(list(self.children()))]
        yield sorted(self.attrs)

    __rich_repr__.angular = True
