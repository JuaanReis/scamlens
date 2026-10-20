from .common import ParseError, unpack, region, section

def parse(data):
    pe = unpack("<I", data, 0x3c)[0]

    if region(data, pe, 4) != b"PE\0\0":
        raise ParseError("invalid PE signature")
    
    machine, count, timestamp, _, _, opt_size, characteristics = unpack("<HHIIIHH", data, pe+4)
    if not 1 <= count <= 96:
        raise ParseError("invalid PE section count")
    
    opt = pe+24
    region(data, opt, opt_size)
    magic = unpack("<H", data, opt)[0]

    if magic not in (0x10b, 0x20b):
        raise ParseError("unsupported PE optional header")
    
    minimum = 112 if magic == 0x20b else 96

    if opt_size < minimum:
        raise ParseError("short PE optional header")
    
    entry = unpack("<I", data, opt+16)[0]
    sections = []

    for i in range(count):
        off = opt+opt_size+i*40
        name = region(data, off, 8).split(b"\0")[0].decode("ascii", "replace")
        vs, va, size, ptr = unpack("<IIII", data, off+8)
        flags = unpack("<I", data, off+36)[0]
        sections.append(section(name, ptr, size, va, vs, flags & 0x20000000, flags & 0x80000000, data))
    
    def rva(value):
        for s in sections:
            delta = value-s['virtual_address']
            if 0 <= delta < s['size']:
                return s['offset']+delta
        raise ParseError("unmapped PE RVA")
    
    def cstring(offset):
        raw = region(data, offset, min(512, len(data)-offset))
        return raw.split(b"\0")[0].decode("ascii", "replace")
    
    imports, warnings = [], []
    directories = opt+minimum
    directory_count = unpack("<I", data, directories-4)[0]
    
    if directory_count > 1 and directories+16 <= opt+opt_size:
        imp_rva, imp_size = unpack("<II", data, directories+8)
        if imp_rva:
            try:
                base = rva(imp_rva)
                for i in range(min(256, max(1, imp_size//20))):
                    original, _, _, dll_name, thunk = unpack("<IIIII", data, base+20*i)
                    
                    if not any((original, dll_name, thunk)):
                        break

                    if dll_name:
                        imports.append(cstring(rva(dll_name)))

                    if not (original or thunk):
                        continue

                    th = rva(original or thunk)
                    width = 8 if magic == 0x20b else 4

                    for j in range(4096):
                        value = unpack("<Q" if width == 8 else "<I", data, th+j*width)[0]

                        if not value:
                            break

                        if not value & (1 << (width*8-1)):
                            imports.append(cstring(rva(value)+2))

            except ParseError as exc:
                warnings.append("partial PE imports: " + str(exc))
    
    end = max(s['offset']+s['size'] for s in sections)

    return dict(format="PE", bits=64 if magic == 0x20b else 32, machine=machine,
                entrypoint=entry, sections=sections, imports=sorted(set(imports)),
                overlay_bytes=max(0, len(data)-end), warnings=warnings,
                signature_status="not_verified", timestamp=timestamp,
                executable_kind="dll" if characteristics & 0x2000 else "image")
