#!/usr/bin/env python3

import copy
import re
from collections import defaultdict as ddict
from contextlib import suppress

from zmech import ZMech
from zmech.disasm import Routine, parse_routine
from zmech.structs import Imm, Var
from zmech.util import from_bytes


def _tr_imm(imm):
    if isinstance(imm, Imm):
        return imm.value
    elif isinstance(imm, int):
        return imm
    return None


ATTRIBUTES = {
    0x00: "WEARABLE",
    0x03: "LONG_DESC_SEEN",
    0x06: "?ROOM",
    0x07: "HIDDEN",
    0x0A: "SURFACE",  # eg you can put things *on* it
    0x0B: "OPEN",  # (as in (eb)[kitchen window] or bottle)
    0x0F: "FLIPPABLE",
    0x10: "READABLE",
    0x11: "?TAKEABLE",
    0x12: "?UNDERWATER",
    0x13: "FILLABLE",
    0x14: "?DOUSABLE",
    0x15: "EDIBLE",
    0x16: "DRINKABLE",
    0x17: "OPENABLE",  # eg doors, windows
    0x18: "CAN_MOVE_ALONG",  # eg cliff, tree, ladder, chimney, etc
    0x19: "CAN_START_FIRE",
    0x1A: "BURNABLE",  # eg coal, paper, etc; as opposed to 0x1f
    0x1B: "BOAT",
    0x1C: "TOOL",
    0x1D: "WEAPON",
    0x1E: "SENTIENT",
    0x1F: "IGNITABLE",  # eg torch, candles, lantern
}


def _attr(code):
    if name := ATTRIBUTES.get(_tr_imm(code)):
        return f":{name}:"
    return code


PROPERTIES = {
    0x2: "?NeverSet_0x2",
    0x4: "?Interactables",
    0x5: "?InteractableObjs",
    0x9: "?Paddr_0x9",
    0xA: "Space",
    0xB: "Description",
    0x11: "OverrideAction",
    0x13: "LandViaBoat",
    0x14: "Exit",
    0x15: "Enter",
    0x16: "Down",
    0x17: "Up",
    0x18: "Southwest",
    0x19: "Southeast",
    0x1A: "Northwest",
    0x1B: "Northeast",
    0x1C: "South",
    0x1D: "West",
    0x1E: "East",
    0x1F: "North",
}


def _prop(code):
    if name := PROPERTIES.get(_tr_imm(code)):
        return f":{name}:"
    return code


# Props:
# 0x2: TODO unknown callable paddr
# 0x4: list-of-[noun-addr, call-paddr] for I guess interactables that aren't oidxs
# 0x5: list-of-oidxs of interactables (eg stairs, chimney, window)
# 0x9: TODO unknown callable paddr
# 0xa: amount of room for putting things in (see prop 0xf)
# 0xb: first-encounter text?
# 0xc: point score value? for taking? see @a3f0 in [a3e0] ; also saved prevGlowLevel for (6e)[sword]
# 0xd: point score value? eg for finding (a3)[large emerald]
# 0xe: paddr of out-in-world description for nouns
# 0xf: size/weight
# 0x10: list-of-adj-codes to I guess disambiguate this noun
# 0x11 callable paddr (interact specialization?):
#   (): override for if this obj is current actor or if this obj is direct or indirect object
#   0x1: override for if this object is parent of current actor (eg cur location, or boat?)
#   0x3: print long/first-visit description
#   0x4: print short/repeat-visit description (probably)
#   0x6: perform "take" failure?
# 0x12: list-of-words, each word is a direct (z)addr to a synonym noun in the dictionary
# DIRECTIONS:
#   see [8aa4], seems to be the "go in X direction" routine
#   len 1: [8ac9] => prop is oidx, call [92b6] $prop (move-to-room routine)
#   len 2: [8ad8] => prop is paddr, print (and don't move)
#   len 3: [8ae5] => prop.words[0] is a call-paddr, call it
#                      rval <> 0 => it's a room oidx, call [92b6] $rval
#                      rval == 0 => don't move
#   len 4: [8b05] => prop.bytes[1] is a GVAR REF, deref it
#                      gval <> 0 => it's a room oidx, move to $prop.bytes[0]
#                      gval == 0 => print prop.words[1] (if non-zero) and don't move
#   len 5: [8b38] => prop.bytes[1] is an obj, test it for attr 0xb (OPEN)
#                      $obj is OPEN => move to $prop.bytes[0]
#                      $obj is CLOSED => print prop.words[1] (default: "The $obj is closed.") and don't move
#   can also have len > 2? not quite sure how it works yet
# 0x13: land via boat?
# 0x14: exit
# 0x15: enter
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
    0: "sp",
    16: "loc",
    17: "score",
    18: "turns",
    27: "pcGameLoop",
    33: "bOpenedCanary",
    41: "pCandleTicker",
    43: "pBrassLampTicker",
    # w[0] -> ???
    # w[1] -> pzMsg to display when timer ticks out
    44: "pzThiefDescrUnconscious",
    45: "pzThiefDescr",
    60: "bMirrorBroken",
    76: "bGoodLuck",
    77: "nDeaths",
    78: "bPlayerDead",
    79: "also_maybe_score",
    82: "bLight",
    85: "nHelloSailors",
    86: "verbosity_superBrief",
    87: "verbosity_maximum",
    107: "?_attr",
    113: "?nounCount",
    114: "?verb_parse_info",
    116: "?cmd_parse_info",
    # w[0] -> 0xff - verb code ?
    # w[1] -> either 0x0 or $verb_parse_info?_v114 (NOT deref'd)
    # w[2] -> noun code for noun 1
    # w[3] -> noun code for noun 2
    # w[4] -> ??? not sure where set, but used at [612e]
    122: "oPrevLoc",
    123: "oPrevDirect",
    124: "phraseStart",  # eg when speaking to another character
    125: "intext",
    126: "parse",
    127: "actor",
    129: "nwords",
    134: "direct",
    135: "indirect",
    136: "action",
    137: "?bPlayerIsGhost",
    144: "player",
    146: "tickTableCur",
    147: "tickTableCur2",
    148: "tick_table",
    156: "bFoundSecretPath",
    157: "bTrollDead",
    159: "bCyclopsHole",
    161: "bBanishedGhosts",
    164: "bBoatDeflated",
    165: "bCyclopsClear",
    168: "lowestDirPropNum",
    170: "pronounTable",
    171: "verbDispatch",
    172: "verbIndirectDispatch",
    173: "grammarTable",
}

ACTIONS = {
    0x00: "verbose",
    0x01: "brief",
    0x02: "super",
    0x03: "diagno",
    0x04: "inventory",
    0x05: "quit",
    0x06: "restart",
    0x07: "restore",
    0x08: "save",
    0x09: "score",
    0x0A: "script",
    0x0B: "unscript",
    0x0C: "version",
    0x0D: "$ve",
    0x0E: "activate",
    0x0F: "again",
    0x10: "answer",
    0x11: "answer X",
    0x12: "put in",
    0x13: "attack X with Y",
    0x14: "back",
    0x15: "blow up X",
    0x16: "turn off",
    0x17: "inflate",
    0x18: "blow in X",
    0x19: "get in boat",
    0x1A: "brush",
    0x1B: "bug",
    0x1C: "burn",
    0x1C: "light X with Y",
    0x1D: "barf",
    0x1E: "climb up X",
    0x1F: "climb down X",
    0x20: "climb X",
    0x21: "climb on boat",
    0x22: "enter X",
    0x23: "close X",
    0x24: "comman X",
    0x25: "count X",
    0x26: "cross X",
    0x27: "cut X with Y",
    0x28: "curse",
    0x28: "curse X",
    0x29: "deflat X",
    0x2A: "break X with Y",
    0x2B: "block in X",
    0x2B: "open X",
    0x2C: "dig X with Y",
    0x2D: "get out of boat",
    0x2E: "disenc X",
    0x2F: "drink X",
    0x30: "drink from X",
    0x31: "drop X",
    0x32: "put X on Y",
    0x33: "eat X",
    0x34: "echo",
    0x35: "enchan X",
    0x36: "enter",
    0x37: "exit",
    0x38: "describe X",
    0x39: "look in X",
    0x3A: "banish X",
    0x3B: "fill X",
    0x3C: "find X",
    0x3D: "chase",
    0x3E: "froboz",
    0x3F: "give X to Y",
    0x40: "give X Y",
    0x41: "hatch X",
    0x42: "hello",
    0x43: "chant",
    0x44: "is X in Y",
    0x45: "jump over X",
    0x46: "kick X",
    0x47: "stab X",
    0x48: "kiss X",
    0x49: "knock on X",
    0x4A: "launch X",
    0x4B: "lean on X",
    0x4C: "leave",
    0x4D: "listen",
    0x4E: "lock X with Y",
    0x4F: "?look underwater",
    0x50: "look on X",
    0x51: "look under X",
    0x52: "look behind X",
    0x53: "read X",
    0x54: "lower X",
    0x55: "grease X with Y",
    0x56: "make X",
    0x57: "melt X with Y",
    0x58: "pull X",
    0x59: "turn X to Y",
    0x5A: "mumble",
    0x5B: "odysse",
    0x5C: "pick X",
    0x5D: "take",
    0x5E: "play X",
    0x5F: "fix X with Y",
    0x60: "plugh",
    0x61: "pour X on Y",
    0x62: "pray",
    0x63: "pump up X",
    0x64: "push X to Y",
    0x65: "push X",
    0x66: "push X under Y",
    0x67: "wear X",
    0x68: "put X behind Y",
    0x69: "lift X",
    0x6A: "molest X",
    0x6B: "read X Y",
    0x6C: "repent",
    0x6D: "ring X",
    0x6E: "touch X",
    0x6F: "tell X",
    0x70: "say",
    0x71: "search X",
    0x72: "send for X",
    0x73: "shake X",
    0x74: "hop",
    0x75: "smell X",
    0x76: "spin X",
    0x77: "spray X on Y",
    0x78: "spray X with Y",
    0x79: "squeez X",
    0x7A: "stand up X",
    0x7B: "stay",
    0x7C: "strike X",
    0x7D: "swim",
    0x7E: "swing X",
    0x7F: "throw X at Y",
    0x80: "throw X Y",
    0x81: "throw X off Y",
    0x82: "attach X to Y",
    0x83: "tie up X with Y",
    0x84: "treasure",
    0x85: "unlock X with Y",
    0x86: "untie X",
    0x87: "wait",
    0x88: "wake up X",
    0x89: "go X",
    0x8A: "go to X",
    0x8B: "go around X",
    0x8C: "wave X",
    0x8D: "win",
    0x8E: "wind up X",
    0x8F: "wish",
    0x90: "yell",
    0x91: "zork",
}


def _action(code):
    if name := ACTIONS.get(_tr_imm(code)):
        return f"[act:{name.upper().replace(' ', '_')}]"
    return code


ROUTINES = {
    0x4E42: ["roll_d100_d300"],
    0x4E5C: ["pick_random_el"],
    0x4F04: ["__start"],
    0x50D0: ["nothing"],
    0x5472: ["set_ticker", 'pcCallback', 'nTicks', 'pTickEl'],
    0x5486: [
        "find_or_create_ticker",
        'pcCallback',
        'bAlsoTick2nd',
        'tickTableEnd',
        'pTickEl',
        'pNewTickEl',
    ],
    0x54C4: ["turn_ticker", 'pTickEl', 'tickTableEnd', 'nTicks', 'bHandledAny'],
    0x552A: ["main_game_loop"],
    0x577C: [
        "perform_action",
        'tmpAction',
        'tmpDirect',
        'tmpIndirect',
        'bHandled',
        'savedAction',
        'savedDirect',
        'savedIndirect',
    ],
    0x6C62: ["is_there_light"],
    0x6EE0: ["print_intro"],
    0x7712: ["handle_eating", 'bEdible', 'bDrinkable'],
    0x78BA: ["remove_object", 'obj', 'bWasLight'],
    0x7E04: ["force_describe_loc_and_contents"],
    0x8C9A: ["describe_loc", "bForceVerbose", "bDoLongDesc"],
    0x8D4E: ["describe_loc_contents", "bForceVerbose"],
    0x8EAA: ["print_contents"],
    0x9062: ["add_to_score"],
    0x92B6: [None, 'oArg'],
    0x9470: [None, 'oArg'],
    0x9530: ["overwrite_prev_direct", "newDirect"],
    0xDEAA: ["brass_lantern_battery_timer"],
    0xDED4: ["candle_timer"],
    0x100F8: [
        "sword_glow",
        "pSwordTickEl",
        "prevGlowLevel",
        "glowLevel",
        "?propNum",
        "propAddr",
        "propLen",
    ],
    0x101C6: ["find_enemies", "loc", "oCur"],
    0x101E0: ["thief_ticker"],
    0x10666: ["player_dies", 'pzMsg'],
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
            case '$action_v136':
                for i in range(1, len(insn.args)):
                    insn.args[i] = _action(insn.args[i])
            case '$loc_v16' | '$direct_v134' | '$indirect_v135' | "$actor_v127":
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
                        s = z.readZ(p * 2)
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
    notes_to_add[0xF5AA].append(f"see [10872]")

    for a in (
        0x4E38,
        0x5018,
        0x506A,
        0x545C,
        0x635E,
        0x947E,
        0x94DC,
        0xECDE,
        0xF4EA,
    ):
        notes_to_add[a].append(f"unused? maybe debugging?")

    # slurp call targets from props 0x2, 0x9, and 0x11
    # TODO slurp call targets for len 3 directions
    for oidx in range(1, max_oidx + 1):
        obj = z.obj(oidx)
        for prop in obj.props():
            if prop.num in [0x2, 0x9, 0x11]:
                if dst := prop.paddr:
                    notes_to_add[dst].append(
                        f"({obj.idx:02x})[{obj.shortname}] {_prop(prop.num)} (prop {hex(prop.num)})"
                    )
                    if prop.num == 0x11:
                        call_args[dst] = 1
            elif prop.num in [0x4]:
                words = prop.words
                for i in range(0, len(words), 2):
                    item = z.readZ(words[i])
                    dst = words[i + 1] * 2
                    notes_to_add[dst].append(
                        f"{obj} {_prop(prop.num)} (prop {hex(prop.num)}) : {item}"
                    )
            elif 0x13 <= prop.num <= 0x1F and prop.len == 3:
                dst = from_bytes(prop.data[:2]) * 2
                if dst:
                    notes_to_add[dst].append(
                        f"({obj.idx:02x})[{obj.shortname}] {_prop(prop.num)} (prop {hex(prop.num)})"
                    )

    for code in range(0, 0x91 + 1):
        dst = z.readW((z.gvar(171), code)) * 2
        if dst:
            notes_to_add[dst].append(
                f"from [5869]: loadw {Var(171)} {_action(code)} -> call"
            )
            call_args[dst] = 0

    for code in range(0, 0x91 + 1):
        dst = z.readW((z.gvar(172), code)) * 2
        if dst:
            notes_to_add[dst].append(
                f"from [5817]: loadw {Var(172)} {_action(code)} -> call"
            )

    # parse all routines, by sequentially scanning through instruction memory
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
    try:
        while True:
            a = z.tell()
            routines[a] = z.readZ()
    except EOFError:
        pass

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
        (0x10B16, None, '(zstrings)'),
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

    # v43 brass lantern timer data
    mem_markers.append((w := z.gvar(43), w + 14, f'{Var(43)}'))

    # v170 pronoun table
    mem_markers.append((w := z.gvar(170), w + 2 + 4 * z.readW(w), f'{Var(170)}'))

    # potential global pointers
    for vidx in range(16, 256):
        if vidx in {35, 170, 27, 43}:
            continue
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
    z.seek(z.gvar(170))
    print(f"{Var(170)}:")
    n = z.readW()
    pronouns = {}
    for _i in range(n):
        dword = z.readW()
        code = z.readW()
        print(f"  {code:02x} : {z.readZ(dword)}")
        pronouns[code] = z.readZ(dword)

    print()
    z.seek(z.gvar(173))
    first_one = z.readW(z.tell())
    n = (first_one - z.tell()) // 2
    print(f"{Var(173)}:")
    verbSentences = ddict(list)
    with z.seek(z.dict_start):
        z.skip(z.readB())
        l = z.readB()
        num = z.readW()
        for _i in range(num):
            w = z.readZ(max=2)
            d = z.read(l - 4)
            if d[0] & 0x40:
                wty = d[0]
                code = d[1] if wty & 0x3 == 0x1 else d[2]
                sentenceTy = 0xFF - code
                verbSentences[sentenceTy].append(w)
    actions = ddict(list)
    for i in range(n):  # just a guess
        base = z.readW()
        with z.seek(base):
            n_els = z.readB()
            # print(f"  : {' '.join(verbSentences[i])}")# {n_els} element(s)")
            for j in range(n_els):
                _root = z.tell()
                n_nouns = z.readB() & 0x3
                data = z.read(6)
                # subj. pronoun, obj. pronoun
                # subj. attr? obj. attr?
                # subj. somesortaflags obj. somesortaflags
                actionCode = z.readB()
                frags = [f"[{actionCode:02x}]"]

                def _add_frags(k):
                    if data[k]:
                        frags.append(pronouns[data[k]])
                        if pronouns[data[k]] == 'out':
                            frags.append('(of)')
                    noun = chr(ord('X') + k)
                    if data[2 + k]:
                        attr = ATTRIBUTES.get(data[2 + k], f"attr:{data[2+k]:02x}")
                        noun += f"<{attr}>"
                    if data[4 + k]:
                        flags = data[4 + k]
                        noun += f"<{hex(flags)}>"
                    frags.append(noun)

                if n_nouns == 0:
                    pass
                elif n_nouns == 1:
                    for k in range(1):
                        _add_frags(k)
                elif n_nouns == 2:
                    for k in range(2):
                        _add_frags(k)
                # print(f"    {frags[0]} {0xff-i:02x} {z.read(8, _root).hex()} {' '.join(frags[1:])}")
                actions[actionCode].append(
                    ' '.join(verbSentences[i]) + ' / ' + ' '.join(frags[1:])
                )
            assert z.readB() == 0
    # print()
    canonical = ddict(list)
    for code, sentences in sorted(actions.items()):
        ss = [s.removesuffix(' / ') for s in sorted(sentences)]
        print(f"  [{code:02x}] {ss[0]}")
        for s in ss:
            canon = []
            canon.append(s.split()[0])
            if m := re.search(r'([a-z]+)?(?: \(of\))? (X)', s):
                canon.extend(filter(None, m.groups()))
            if m := re.search(r'([a-z]+)?(?: \(of\))? (Y)', s):
                canon.extend(filter(None, m.groups()))
            canonical[' '.join(canon)].append(code)
        for s in ss[1:]:
            print(f"       {s}")
    print()
    for canon, codes in canonical.items():
        codes = ', '.join(f"{code:02x}" for code in codes)
        print(f"{canon} ;; [{codes}]")

    # dump global variables
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
        main(fname)
