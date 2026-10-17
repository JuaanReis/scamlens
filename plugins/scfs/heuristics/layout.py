from .registry import register
from .content import result

@register("embedded_executable", "structure", "medium", 1.0, group="binary_layout")
def embedded_executable(ctx):
    if ctx.target.structure['format'] == 'script':
        return result(None,"Não aplicável a scripts.")
    offsets=ctx.target.features.get('embedded_pe_offsets',[])
    return result(.4 if offsets else 0,"Cabeçalho PE embutido validado parcialmente; instaladores também incluem executáveis.",
                  [f"PE header at file offset {offset}" for offset in offsets])

@register("overlapping_sections", "structure", "medium", 1.5, group="binary_layout")
def overlapping_sections(ctx):
    if ctx.target.structure['format'] != 'PE':
        return result(None,"Sobreposição é avaliada somente em seções PE, não em segmentos ELF/Mach-O.")
    sections=ctx.target.structure['sections']
    hits=[]
    for i,left in enumerate(sections):
        for right in sections[i+1:]:
            for field,size in (('offset','size'),('virtual_address','virtual_size')):
                if left[size] and right[size] and max(left[field],right[field]) < min(left[field]+left[size],right[field]+right[size]):
                    hits.append(f"{left['name']} / {right['name']} ({field})")
    return result(.65 if hits else 0,"Seções PE sobrepostas em arquivo ou memória.",hits)
