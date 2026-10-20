import math
import re
import struct
from collections import Counter

class ParseError(ValueError):
    pass

def unpack(fmt, data, offset):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ParseError("truncated executable structure")
    return struct.unpack_from(fmt, data, offset)

def region(data, offset, size):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ParseError("executable region outside file")
    return data[offset:offset+size]

def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return round(-sum((c/n) * math.log2(c/n) for c in Counter(data).values()), 4)

def extract_strings(data, limit):
    result = []
    for pattern, encoding in ((rb"[\x20-\x7e]{5,512}", "ascii"),
                               (rb"(?:[\x20-\x7e]\x00){5,512}", "utf-16le")):
        for match in re.finditer(pattern, data):
            if len(result) >= limit:
                return result, True
            result.append(match.group().decode(encoding))
    return result, False

def section(name, offset, size, virtual_address, virtual_size, executable, writable, data):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ParseError("executable region outside file")
    
    if size <= 65536:
        content = data[offset:offset+size]
    else:

        content = b"".join(data[offset+((size-16384)*i//3):offset+((size-16384)*i//3)+16384]
                           for i in range(4))
                           
    return dict(name=name, offset=offset, size=size, virtual_address=virtual_address,
                virtual_size=virtual_size, executable=bool(executable), writable=bool(writable),
                entropy=entropy(content), entropy_sample_bytes=len(content))
