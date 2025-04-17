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
