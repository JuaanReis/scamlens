from .common import ParseError, unpack, region, section

MAGICS = {b"\xce\xfa\xed\xfe": ("<",32), b"\xcf\xfa\xed\xfe": ("<",64),
          b"\xfe\xed\xfa\xce": (">",32), b"\xfe\xed\xfa\xcf": (">",64)}

FAT = {b"\xca\xfe\xba\xbe": (">",False), b"\xbe\xba\xfe\xca": ("<",False),
       b"\xca\xfe\xba\xbf": (">",True), b"\xbf\xba\xfe\xca": ("<",True)}

def parse(data):
    if data[:4] in FAT:
        endian, wide = FAT[data[:4]]
        count = unpack(endian+"I", data, 4)[0]

        if not 1 <= count <= 32:
            raise ParseError("invalid Mach-O universal architecture count")
        
        slices = []
        for i in range(count):
            pos = 8+i*(32 if wide else 20)
            fields = unpack(endian+("IIQQII" if wide else "IIIII"), data, pos)
            off, size = fields[2:4]
            part = region(data, off, size)

            if part[:4] not in MAGICS:
                raise ParseError("invalid Mach-O universal slice")
            
            slices.append(parse(part))

        return dict(format="Mach-O universal", bits=None, machine=None, entrypoint=None,
                    sections=[dict(s, name=f"arch{idx}:"+s['name']) for idx,b in enumerate(slices) for s in b['sections']],
                    imports=sorted({x for b in slices for x in b['imports']}), overlay_bytes=None,
                    warnings=[], signature_status="not_verified", executable_kind="universal", architectures=slices)
    
    endian, bits = MAGICS[data[:4]]
    machine, _, kind, count, command_bytes, _ = unpack(endian+"IIIIII", data, 4)
    if kind not in (2, 6, 8):
        raise ParseError("Mach-O is not executable/dylib/bundle")
    
    pos = 32 if bits == 64 else 28
    end = pos+command_bytes
    region(data, pos, command_bytes)
    if count > 4096:
        raise ParseError("too many Mach-O commands")
    
    sections, imports = [], []
    for i in range(count):
        cmd, size = unpack(endian+"II", data, pos)

        if size < 8 or pos+size > end:
            raise ParseError("invalid Mach-O load command")
        
        if cmd in (1, 0x19):
            minimum = 72 if cmd == 0x19 else 56

            if size < minimum:
                raise ParseError("short Mach-O segment")
            
            name = region(data, pos+8, 16).split(b"\0")[0].decode("ascii", "replace")
            va, vs, off, fs, maxprot, prot = unpack(endian+("QQQQII" if cmd == 0x19 else "IIIIII"), data, pos+24)
            sections.append(section(name, off, fs, va, vs, prot & 4, prot & 2, data))

        if cmd in (0xc, 0x18, 0x80000018, 0x8000001f):
            nameoff = unpack(endian+"I", data, pos+8)[0]

            if not 12 <= nameoff < size:
                raise ParseError("invalid Mach-O dylib name")
            
            imports.append(region(data, pos+nameoff, size-nameoff).split(b"\0")[0].decode("utf8", "replace"))
        
        if len(sections) > 128:
            raise ParseError("too many Mach-O segments")
        
        pos += size
        
    if not sections:
        raise ParseError("Mach-O has no segments")
    
    return dict(format="Mach-O", bits=bits, machine=machine, entrypoint=None,
                sections=sections, imports=imports, overlay_bytes=None, warnings=[],
                signature_status="not_verified", executable_kind="image")
