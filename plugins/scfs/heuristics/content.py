import json
import re
from pathlib import Path
from .registry import register

INDICATORS = json.loads((Path(__file__).resolve().parents[1] / "datasets" / "indicators.json").read_text())

def matches(ctx, group):
    return [term for term in INDICATORS[group] if term in ctx.target.evidence_text]

def result(score, message, evidence=()):
    return score, message, list(evidence)[:12]

@register("process_injection", "behavior", "high", 3.0, ("injection",), group="injection")
def process_injection(ctx):
    hits = matches(ctx, "injection")
    return result(1.0 if len(hits) >= 3 else .65 if len(hits) >= 2 else .15 if hits else 0,
                  "Combinação de APIs de injeção; presença estática não prova execução.", hits)

@register("credential_access", "behavior", "high", 3.0, ("credentials",), group="credentials")
def credential_access(ctx):
    hits = matches(ctx, "credentials")
    return result(.95 if len(hits) >= 2 else .3 if hits else 0, "Indicadores de acesso a credenciais.", hits)

@register("persistence", "behavior", "medium", 1.8, group="persistence")
def persistence(ctx):
    hits = matches(ctx, "persistence")
    return result(.75 if len(hits) >= 2 else .4 if hits else 0, "Indicadores de persistência.", hits)

@register("defense_evasion", "behavior", "high", 2.5, group="defense_evasion")
def defense_evasion(ctx):
    hits = matches(ctx, "defense_evasion")
    return result(.95 if len(hits) >= 2 else .6 if hits else 0, "Indicadores de alteração de defesas ou logs.", hits)

@register("destructive_commands", "behavior", "high", 3.0, group="impact")
def destructive_commands(ctx):
    hits = matches(ctx, "destructive")
    strong = [x for x in hits if x != "remove-item -recurse"]
    return result(1.0 if len(strong) >= 2 else .7 if strong else .2 if hits else 0,
                  "Comandos potencialmente destrutivos; limpeza recursiva isolada tem menor confiança.", hits)

@register("download_and_execute", "behavior", "high", 2.5, group="execution")
def download_and_execute(ctx):
    network, execution = matches(ctx, "network"), matches(ctx, "execution")
    # URL strings and process spawning are ubiquitous in legitimate software.
    specific = [x for x in network if x in INDICATORS["download"]]
    dynamic = [x for x in execution if x in INDICATORS["dynamic_execution"]]
    score = .85 if specific and dynamic else .45 if specific and execution else .12 if network and execution else 0
    return result(score, "Coocorrência de download e execução; não demonstra fluxo de dados.", network+execution)

@register("encoded_execution", "obfuscation", "high", 2.0, group="execution")
def encoded_execution(ctx):
    encoded, execution = matches(ctx, "obfuscation"), matches(ctx, "execution")
    return result(.85 if encoded and execution else .2 if encoded else 0, "Codificação combinada com execução dinâmica.", encoded+execution)

@register("anti_analysis", "obfuscation", "medium", 1.0, group="obfuscation")
def anti_analysis(ctx):
    hits = matches(ctx, "anti_analysis")
    return result(.5 if len(hits) >= 2 else .2 if hits else 0, "Indicadores de depuração ou virtualização.", hits)

@register("long_encoded_literal", "obfuscation", "low", .6, group="obfuscation")
def long_encoded_literal(ctx):
    text = ctx.target.evidence_text
    hit = re.search(r"[A-Za-z0-9+/]{300,}={0,2}", text)
    return result(.3 if hit else 0, "Literal longo compatível com base64; pode ser recurso legítimo.", ["literal >= 300 caracteres"] if hit else [])
