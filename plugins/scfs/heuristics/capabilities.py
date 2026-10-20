"""Capability indicators: cooccurrence is evidence, never proof of execution."""
from .registry import register
from .content import matches, result

def pair(ctx, first, second, combined, single):
    a, b = matches(ctx, first), matches(ctx, second)
    return (combined if a and b else single if a else 0), a+b

@register("input_capture", "collection", "medium", 1.8, group="collection", attack="T1056.001")
def input_capture(ctx):
    score,hits = pair(ctx,"keyboard","key_context",.8,.15)
    return result(score,"APIs de teclado combinadas com contexto de captura; ferramentas de acessibilidade também as usam.",hits)

@register("screen_capture", "collection", "low", .8, group="collection", attack="T1113")
def screen_capture(ctx):
    score,hits = pair(ctx,"screen","screen_context",.5,.15)
    return result(score,"Indicadores de captura de tela, comuns também em software legítimo.",hits)

@register("clipboard_capture", "collection", "low", .8, group="collection", attack="T1115")
def clipboard_capture(ctx):
    score,hits = pair(ctx,"clipboard","clipboard_context",.45,.12)
    return result(score,"Leitura/monitoramento de clipboard; não implica roubo de dados.",hits)

@register("service_installation", "persistence", "medium", 1.5, group="persistence", attack="T1543.003")
def service_installation(ctx):
    score,hits = pair(ctx,"service","service_context",.7,.2)
    return result(score,"Criação de serviços combinada com configuração; instaladores legítimos fazem o mesmo.",hits)

@register("token_manipulation", "privilege", "high", 2.5, group="privilege", attack="T1134")
def token_manipulation(ctx):
    score,hits = pair(ctx,"tokens","privilege_context",.85,.25)
    return result(score,"APIs de token/impersonação combinadas com contexto de privilégios.",hits)

@register("ransomware_artifacts", "impact", "high", 3.0, group="impact")
def ransomware_artifacts(ctx):
    note,crypto,mutation = matches(ctx,"ransom_note"),matches(ctx,"encryption"),matches(ctx,"file_mutation")
    score = 1.0 if note and crypto and mutation else .7 if note and crypto else .2 if note else 0
    return result(score,"Nota de resgate combinada com criptografia e alteração de arquivos; criptografia isolada não pontua.",note+crypto+mutation)

@register("data_exfiltration", "exfiltration", "high", 2.5, group="exfiltration")
def data_exfiltration(ctx):
    upload,sensitive,archive = matches(ctx,"upload"),matches(ctx,"sensitive_data"),matches(ctx,"archive")
    score = .9 if upload and sensitive and archive else .7 if upload and sensitive else 0
    return result(score,"Coocorrência de envio, dados sensíveis e/ou arquivo compactado; não prova fluxo entre eles.",upload+sensitive+archive if score else [])

@register("suspicious_lolbin", "execution", "high", 2.5, group="execution", attack="T1218")
def suspicious_lolbin(ctx):
    bins,network,dynamic = matches(ctx,"lolbins"),matches(ctx,"network"),matches(ctx,"obfuscation")
    score = .85 if bins and network and dynamic else .55 if bins and network else .1 if bins else 0
    return result(score,"Binário do sistema junto a rede/codificação; menção isolada tem peso baixo.",bins+network+dynamic if bins else [])

@register("dynamic_import_resolution", "obfuscation", "low", .8, group="obfuscation")
def dynamic_import_resolution(ctx):
    lookup,loader = matches(ctx,"dynamic_loader"),matches(ctx,"library_loader")
    if ctx.target.structure['format'] == 'script':
        return result(None,"Regra de resolução dinâmica aplicável a binários.")
    # Even the full combination is weak: plugins and runtimes routinely use it.
    return result(.3 if lookup and loader else 0,"Resolução dinâmica de símbolos/bibliotecas; comum em plugins legítimos.",lookup+loader if lookup and loader else [])
