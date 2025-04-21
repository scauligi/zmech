import io
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import overload

from .decoder import readInsn
from .structs import Frame, Imm, Obj, Var
from .util import _s, _u, from_bytes, printd, to_bytes
from .vm import doInsn
from .zscii import zdecode


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
        self.dict_start = 0
        self.abbrev_start = 0

        self.revision = 0
        self.serial = None

        self.seps = None
        self.dict = None
        self.abbrevs = None
        self.globals = None
        self.object_table = None

        self.default_props = None

        self.print_buffer = ""
        self.frames = []
        self.ended = False

    def load(self):
        self.himem = self.readW(0x04)
        self.init_pc = self.readW(0x06)
        self.dict_start = self.readW(0x08)
        self.object_table = self.readW(0x0A)
        self.globalmem = self.readW(0x0C)
        self.staticmem = self.readW(0x0E)
        self.abbrev_start = self.readW(0x18)

        self.revision = self.readW(0x02)
        self.serial = self.read(6, 0x12).decode('ascii')

        self.load_dictionary()
        self.load_abbrevs()
        with self.seek(self.object_table):
            self.default_props = {}
            for n in range(1, 32):
                self.default_props[n] = self.readW()

        self.print_buffer = ""
        self.frames = [Frame([], -1, Var(-1))]
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

    @contextmanager
    def _returner(self, saved):
        try:
            yield
        finally:
            self.seek(saved)

    def seek(self, addr):
        """If you use this as a context manager, it'll pop you back to where you were before.
        If you pass None for the addr though then it won't do that (to make other helper functions easier to write).
        """
        if addr is None:
            return nullcontext()
        saved = self.tell()
        self.fp.seek(addr, 0)
        return self._returner(saved)

    def skip(self, n):
        self.fp.seek(n, 1)

    @overload
    def read(self, sz, addr=..., signed: None = ...) -> bytes: ...
    @overload
    def read(self, sz, addr=..., signed: bool = ...) -> int: ...
    def read(self, sz, addr=None, signed=None):
        with self.seek(addr):
            res = self.fp.read(sz)
            if not res:
                raise EOFError()
            if signed is not None:
                res = from_bytes(res, signed=signed)
            return res

    def dump(self, addr):
        print(f"{addr:04x} ", self.read(16, addr).hex(' '))

    def dumpline(self, addr):
        addr &= ~0xF
        print(f"{addr:04x} ", self.read(16, addr).hex(' ', 2))

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
        b = to_bytes(val, 1)
        with self.seek(addr):
            self.fp.write(b)

    def writeW(self, addr, val):
        if isinstance(addr, (tuple, list)) and len(addr) == 2:
            addr = addr[0] + 2 * addr[1]
        b = to_bytes(val, 2)
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
        with self.seek(addr):
            res = zdecode(
                self._yieldW(max=max), abbrevs=(self.abbrevs if use_abbrevs else None)
            )
        return res

    def gvar(self, vidx):
        "NOTE: this uses the var number (index + 16), not the actual index of the global itself"
        assert 16 <= vidx < 256
        return self.readW(self.globalmem + 2 * (vidx - 16))

    def obj(self, oidx):
        assert 0 < oidx < 256
        return Obj(self, oidx)

    def load_dictionary(self):
        self.seps = set()
        self.dict = {}
        with self.seek(self.dict_start):
            n = self.readB()
            for _ in range(n):
                zc = self.readB()
                self.seps.add(chr(zc))
            entry_length = self.readB()
            num_entries = self.readW()
            for _ in range(num_entries):
                addr = self.tell()
                w = self.readZ(max=2)
                data = self.read(entry_length - 4)
                self.dict[w] = addr

    def load_abbrevs(self):
        self.abbrevs = []
        with self.seek(self.abbrev_start):
            for _ in range(32 * 3):
                addr = self.readW()
                self.abbrevs.append(self.readZ(addr * 2, use_abbrevs=False))

    def readInsn(self, addr=None):
        with self.seek(addr):
            return readInsn(self)

    @property
    def stack(self):
        return self.frames[-1].stack

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

    def print(self, s):
        if not s:
            return
        ss = s.split('\n')
        ss[0] = self.print_buffer + ss[0]
        for s in ss[:-1]:
            print(s)
        self.print_buffer = ss[-1]

    def show_status(self):
        # technically, check bit 1 of Flags 1 as to whether this is a score or time game
        loc = self.obj(self.gvar(16))
        score = _s(self.gvar(17))
        turns = self.gvar(18)
        print('\x1b[?1048h', end='', flush=True)
        print('\x1b[1;1H', end='', flush=True)
        print('\x1b[K', end='', flush=True)
        print('\x1b[7m', end='', flush=True)
        print(f"{loc!s} / {score} / {turns}", end='', flush=True)
        print('\x1b[0m', end='', flush=True)
        print('\x1b[?1048l', end='', flush=True)

    def prompt(self):
        self.show_status()
        return input(self.print_buffer)

    def step(self):
        insn = self.readInsn()
        assert insn, "insn is None???"
        try:
            doInsn(self, insn)
        except Exception as e:
            frag = f"while executing {insn.name!r} at 0x{insn.addr:04x}"
            if e.args:
                # e.args = (str(e.args[0]) + frag, *e.args[1:])
                e.args = (*e.args, frag)
            else:
                e.args = (frag,)
            raise
