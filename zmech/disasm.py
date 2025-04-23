from attrs import define, field

from .structs import Insn

BB_END = "ret jump rtrue rfalse print_ret ret_popped".split()
BB_COULDFAIL = "restore restart quit".split()


@define
class Routine:
    header: int | None
    locals: list[int] = field(factory=list)
    args: int | None = None
    insns: list = field(factory=list)
    bbs: set = field(factory=set)
    back_jumps: set = field(factory=set)
    calls: list[Insn] = field(factory=list)
    notes: list[str] = field(factory=list)

    def extend(self, o):
        assert o.header is None
        self.insns.extend(o.insns)
        self.bbs.add(o.insns[0].addr)
        self.bbs.update(o.bbs)
        self.calls.extend(o.calls)
        self.notes.extend(o.notes)


def parse_routine(z, addr=None, header=True, r=None):
    with z.seek(addr):
        if r is None:
            r = Routine(z.tell() if header else None)
            if header:
                nargs = z.readB()
                assert nargs <= 15
                r.locals.extend(z.readW() for _ in range(nargs))
        else:
            r.bbs.add(z.tell())
        seen = {insn.addr for insn in r.insns}
        could_have_failed = False
        while True:
            insn = z.readInsn()
            if not insn:
                break
            r.insns.append(insn)
            seen.add(insn.addr)
            if could_have_failed:
                r.bbs.add(insn.addr)
                could_have_failed = False
            if insn.name == "call" and insn.dst:
                r.calls.append(insn)
            elif insn.dst is not None:
                r.bbs.add(insn.dst)
                if insn.dst < insn.addr:
                    r.back_jumps.add(insn.dst)
            if insn.name in BB_END:
                if seen.issuperset(r.bbs):
                    break
            if insn.name in BB_COULDFAIL:
                could_have_failed = True
    return r
