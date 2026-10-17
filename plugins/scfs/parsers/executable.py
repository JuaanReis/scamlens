from pathlib import Path
from . import pe, elf, macho
from .common import ParseError, entropy

SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".py"}

def parse(data, name):
    if data[:2] == b"MZ":
        return pe.parse(data)
    
    if data[:4] == b"\x7fELF":
        return elf.parse(data)
    
    if data[:4] in macho.MAGICS or data[:4] in macho.FAT:
        return macho.parse(data)
    
    if Path(name).suffix.lower() in SCRIPT_EXTENSIONS or data.startswith(b"#!"):
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                if not data.startswith((b"\xff\xfe", b"\xfe\xff")):
                    raise ValueError("not UTF-16")
                
                text = data.decode("utf-16")
            except (ValueError, UnicodeError):
                raise ParseError("script must be UTF-8 or BOM-marked UTF-16") from None
            
        if "\x00" in text:
            raise ParseError("binary content in script")
        
        return dict(format="script", language=Path(name).suffix.lower() or "shebang",
                    bits=None, machine=None, entrypoint=None, sections=[], imports=[],
                    overlay_bytes=None, warnings=[], signature_status="not_verified",
                    executable_kind="script", text=text)

    raise ParseError("unsupported format (expected PE, ELF, Mach-O or executable script)")
