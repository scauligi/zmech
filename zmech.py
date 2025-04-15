import contextlib
from pathlib import Path

from attrs import define, field


@define
class Obj:
    idx: int
    shortname: str
    parent: int
    sibling: int
    child: int
    attrs: list = field(factory=list)
    props: dict = field(factory=dict)


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
        self.fp = Path(fname).open('rb')
        self._loaded = False

        self.himem = 0
        self.staticmem = 0
        self.globalmem = 0
        self.init_pc = 0

        self.dict = None
        self.abbrevs = None
        self.globals = None

        self.default_props = None
        self.objects = None

    def load(self):
        self.himem = self.readW(0x04)
        self.init_pc = self.readW(0x06)
        # self.load_dictionary()
        self.globalmem = self.readW(0x0C)
        self.staticmem = self.readW(0x0E)

        self.load_abbrevs()  # 0x18
        self.load_objects()  # 0x0a, but do this after abbrevs
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

    def readB(self, addr=None, signed=False):
        return self.read(1, addr=addr, signed=signed)

    def readW(self, addr=None, signed=False):
        return self.read(2, addr=addr, signed=signed)

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

    def load_objects(self):
        object_table = self.readW(0x0A)
        with self.seek(object_table):
            self.default_props = {}
            for n in range(31, 0, -1):
                self.default_props[n] = self.readW()
            self.objects = {}
            first_proplistp = 0
            for idx in range(1, 256):
                if first_proplistp and self.tell() >= first_proplistp:
                    break
                attr_int = int.from_bytes(self.read(4), 'big')
                attrs = []
                for n in range(8 * 4):
                    if attr_int & (0x80000000 >> n):
                        attrs.append(n)
                parent = self.readB()
                sibling = self.readB()
                child = self.readB()
                proplistp = self.readW()
                if not first_proplistp:
                    first_proplistp = proplistp
                with self.seek(proplistp):
                    textlength = self.readB()
                    shortname = self.readZ(max=textlength)
                    props = {}
                    while True:
                        szbyte = self.readB()
                        if not szbyte:
                            break
                        propnum = szbyte & 0b11111
                        nbytes = (szbyte >> 5) + 1
                        propdata = self.read(nbytes)
                        props[propnum] = propdata
                self.objects[idx] = Obj(
                    idx, shortname, parent, sibling, child, attrs, props
                )

    def load_abbrevs(self):
        self.abbrevs = []
        abbrev_start = self.readW(0x18)
        with self.seek(abbrev_start):
            for _ in range(32 * 3):
                addr = self.readW()
                self.abbrevs.append(self.readZ(addr * 2, use_abbrevs=False))


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        z = ZMech(sys.argv[1])
        z.load()
