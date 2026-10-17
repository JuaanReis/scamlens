from .common import ParseError, unpack, region, section

def parse(data):
    cls, byteorder = region(data, 4, 2)
    if cls not in (1, 2) or byteorder not in (1, 2):
        raise ParseError("invalid ELF identification")
    endian = "<" if byteorder == 1 else ">"
    bits = 64 if cls == 2 else 32
    fmt = endian + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH")
    kind, machine, _, entry, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, names_index = unpack(fmt, data, 16)
    if kind not in (2, 3):
        raise ParseError("ELF is not an executable or shared object")
    expected = 56 if bits == 64 else 32
    if phnum > 128 or (phnum and phsize < expected):
        raise ParseError("invalid ELF program table")
    sections = []
    for i in range(phnum):
        pos = phoff+i*phsize
        if bits == 64:
            typ, flags, off, va, _, size, memsize, _ = unpack(endian+"IIQQQQQQ", data, pos)
        else:
            typ, off, va, _, size, memsize, flags, _ = unpack(endian+"IIIIIIII", data, pos)
        if typ == 1:
            sections.append(section("LOAD_"+str(i), off, size, va, memsize, flags & 1, flags & 2, data))
    if not sections:
        raise ParseError("ELF has no loadable segments")
    return dict(format="ELF", bits=bits, machine=machine, entrypoint=entry,
                sections=sections, imports=[], overlay_bytes=None, warnings=[],
                signature_status="not_applicable", executable_kind="image" if kind == 2 else "shared_or_pie")
