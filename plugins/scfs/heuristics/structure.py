from pathlib import Path
from .registry import register
from .content import result, INDICATORS

@register("writable_executable", "structure", "high", 2.0, group="binary_layout")
def writable_executable(ctx):
    sections = ctx.target.structure['sections']
    if ctx.target.structure['format'] == 'script':
        return result(None, "Não aplicável a scripts.")
    hits = [s['name'] for s in sections if s['writable'] and s['executable']]
    return result(.7 if hits else 0, "Região simultaneamente gravável e executável.", hits)

@register("packed_executable", "structure", "medium", 1.2, group="obfuscation")
def packed_executable(ctx):
    sections = ctx.target.structure['sections']
    if ctx.target.structure['format'] == 'script':
        return result(None, "Não aplicável a scripts.")
    names = [s['name'] for s in sections if any(x in s['name'].casefold() for x in INDICATORS['packers'])]
    high = [s['name'] for s in sections if s['executable'] and s['size'] >= 4096 and s['entropy'] >= 7.2]
    return result(.6 if names and high else .35 if names else .25 if high else 0,
                  "Empacotamento/entropia são sinais fracos isoladamente.", names+high)

@register("entrypoint_permissions", "structure", "medium", 1.0, group="binary_layout")
def entrypoint_permissions(ctx):
    s = ctx.target.structure
    entry = s.get('entrypoint')
    if entry is None or entry == 0:
        return result(None, "Entrypoint indisponível ou zero (possível biblioteca).")
    mapped = [x for x in s['sections'] if x['virtual_address'] <= entry < x['virtual_address']+max(x['virtual_size'], x['size'])]
    bad = not mapped or not any(x['executable'] for x in mapped)
    return result(.6 if bad else 0, "Entrypoint fora de região executável." if bad else "Entrypoint mapeado em região executável.")

@register("disguised_filename", "identity", "medium", 1.0, group="masquerading")
def disguised_filename(ctx):
    name = ctx.target.name.casefold()
    stems = Path(name).stem
    hits = [x for x in ('.pdf', '.jpg', '.png', '.doc', '.docx', '.txt') if stems.endswith(x)]
    bidi = any(x in name for x in ('\u202e', '\u202d', '\u2066', '\u2067'))
    return result(.65 if bidi else .5 if hits else 0, "Nome com possível disfarce de extensão ou controle bidirecional.", hits+(['bidi control'] if bidi else []))

@register("external_reputation", "reputation", "high", 4.0, group="reputation")
def external_reputation(ctx):
    rep = ctx.target.reputation
    if rep is None:
        return result(None, "Provedor não configurado, indisponível ou hash desconhecido.")
    return result(rep['malicious']/rep['total'], "Fração de detecções externas; motores podem ser correlacionados.", [f"{rep['source']}: {rep['malicious']}/{rep['total']}"])
