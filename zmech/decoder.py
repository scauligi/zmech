from .structs import Imm, Insn, Str, Var


def readInsn(z):
    insn = Insn(addr=z.tell())
    opcode = z.readB()
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
                c = z.readB()
                insn.args.append(Imm(c))
            elif opclass in (0x4, 0x6):  # var
                vidx = z.readB()
                insn.args.append(Var(vidx))
            # second arg
            if opclass in (0x0, 0x4):  # small constant
                c = z.readB()
                insn.args.append(Imm(c))
            elif opclass in (0x2, 0x6):  # var
                vidx = z.readB()
                insn.args.append(Var(vidx))
        else:
            optys = z.readB()
            optys = f"{optys:08b}"
            # XXX not sure why I'm seeing more than two
            optys = [optys[:2], optys[2:4], optys[4:6], optys[6:8]]
            for opty in optys:
                if opty == '00':  # large constant
                    c = z.readW()
                    insn.args.append(Imm(c))
                elif opty == '01':  # small constant
                    c = z.readB()
                    insn.args.append(Imm(c))
                elif opty == '10':  # var
                    vidx = z.readB()
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
            c = z.readW(signed=True)
            insn.args.append(Imm(c))
        elif opclass == 0x9:  # small constant
            c = z.readB(signed=False)
            insn.args.append(Imm(c))
        elif opclass == 0xA:  # var
            vidx = z.readB()
            insn.args.append(Var(vidx))
        if opname == 'jump':
            dst = z.tell() + c - 2
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
            s = z.readZ()
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
        optys = z.readB()
        optys = f"{optys:08b}"
        optys = [optys[:2], optys[2:4], optys[4:6], optys[6:8]]
        for opty in optys:
            if opty == '00':  # large constant
                c = z.readW()
                insn.args.append(Imm(c))
            elif opty == '01':  # small constant
                c = z.readB()
                insn.args.append(Imm(c))
            elif opty == '10':  # var
                vidx = z.readB()
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
    if ' ->' in opname:
        # store target
        vidx = z.readB()
        insn.out = Var(vidx)
    if ' ?' in opname:
        # jump label
        lcode = z.readB()
        br_dir = lcode & 0x80  # 0 -> br if false, 1 -> br if true
        insn.br_dir = bool(br_dir)
        off = lcode & 0x3F
        if not (lcode & 0x40):
            off = (off << 8) | z.readB()
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
            dst = z.tell() + off - 2
            insn.dst = dst
    insn.name = opname.split()[0]
    insn.end = z.tell()
    return insn
