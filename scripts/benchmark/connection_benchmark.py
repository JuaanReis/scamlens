from __future__ import annotations
import json
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from providers.http.connect import request
from providers.dns.info_dns import get_dns_info
from providers.ssl.info_ssl import get_ssl_cert
from providers.rdap.fetch_rdap import fetch_rdap

TARGETS = [
    "https://www.google.com/",   
    "https://github.com/",         
    "https://expired.badssl.com/", 
    "http://neverssl.com/",      
]

ITERATIONS = 10       
WARMUP_ITERATIONS = 2   
REGRESSION_BASELINE = Path(__file__).parent / "benchmark_baseline.json"
REGRESSION_TOLERANCE = 0.25 

BUDGETS_S = {
    "http": 2.0,
    "dns": 1.0,
    "ssl": 2.0,
    "rdap": 3.0,
}

PROVIDERS: dict[str, Callable[[str], Any]] = {
    "http": lambda host: request("get", host),
    "dns": lambda host: get_dns_info(host),
    "ssl": lambda host: get_ssl_cert({"hostname": host}),
    "rdap": lambda host: fetch_rdap(host),
}

@dataclass
class Sample:
    target: str
    provider: str
    elapsed: float | None   
    error: str | None = None

def timed_call(func: Callable, *args: Any, **kwargs: Any) -> tuple[Any, float, str | None]:
    start = time.perf_counter()
    try:
        result = func(*args, **kwargs)
        return result, time.perf_counter() - start, None
    except Exception as exc:  # providers batem em rede — benchmark de verdade sobrevive a falha
        return None, time.perf_counter() - start, f"{type(exc).__name__}: {exc}"

def run_samples(targets: list[str], iterations: int, warmup: int) -> list[Sample]:
    samples: list[Sample] = []
    for target in targets:
        for name, fn in PROVIDERS.items():
            for i in range(warmup + iterations):
                _, elapsed, error = timed_call(fn, target)
                if i < warmup:
                    continue  # descarta as rodadas de cold-start
                samples.append(Sample(target, name, None if error else elapsed, error))
    return samples

def summarize(samples: list[Sample]) -> dict:
    summary: dict = {}
    by_provider: dict[str, list[float]] = {}
    for s in samples:
        if s.elapsed is not None:
            by_provider.setdefault(s.provider, []).append(s.elapsed)

    for provider, values in by_provider.items():
        values.sort()
        summary[provider] = {
            "n": len(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "p95": values[max(int(len(values) * 0.95) - 1, 0)],
            "min": values[0],
            "max": values[-1],
        }

    errors = [s for s in samples if s.error]
    summary["_errors"] = [
        {"target": e.target, "provider": e.provider, "error": e.error} for e in errors
    ]
    summary["_error_rate"] = len(errors) / len(samples) if samples else 0.0
    return summary

def check_budgets(summary: dict) -> list[str]:
    violations = []
    for provider, budget in BUDGETS_S.items():
        stats = summary.get(provider)
        if not stats:
            continue
        if stats["p95"] > budget:
            violations.append(f"{provider}: p95={stats['p95']:.2f}s excede orçamento de {budget:.2f}s")
    return violations

def check_regression(summary: dict, baseline_path: Path = REGRESSION_BASELINE,
                      tolerance: float = REGRESSION_TOLERANCE) -> list[str]:
    if not baseline_path.exists():
        return []
    baseline = json.loads(baseline_path.read_text())
    regressions = []
    for provider, stats in summary.items():
        if provider.startswith("_") or provider not in baseline:
            continue
        old_p95 = baseline[provider]["p95"]
        new_p95 = stats["p95"]
        if old_p95 and new_p95 > old_p95 * (1 + tolerance):
            pct = (new_p95 / old_p95 - 1) * 100
            regressions.append(f"{provider}: p95 foi de {old_p95:.2f}s para {new_p95:.2f}s (+{pct:.0f}%)")
    return regressions

def save_baseline(summary: dict, path: Path = REGRESSION_BASELINE) -> None:
    clean = {k: v for k, v in summary.items() if not k.startswith("_")}
    path.write_text(json.dumps(clean, indent=2))

def print_report(summary: dict) -> None:
    print(f"\n{'Provider':<10}{'n':<5}{'mean':<8}{'median':<8}{'p95':<8}{'stdev':<8}{'min':<8}{'max':<8}")
    for provider, stats in summary.items():
        if provider.startswith("_"):
            continue
        print(
            f"{provider:<10}{stats['n']:<5}{stats['mean']:<8.3f}{stats['median']:<8.3f}"
            f"{stats['p95']:<8.3f}{stats['stdev']:<8.3f}{stats['min']:<8.3f}{stats['max']:<8.3f}"
        )
    if summary["_errors"]:
        print(f"\n{len(summary['_errors'])} erro(s) ({summary['_error_rate'] * 100:.1f}% das chamadas):")
        for e in summary["_errors"]:
            print(f"  {e['provider']} @ {e['target']}: {e['error']}")

def test_provider_latency_within_budget():
    samples = run_samples(TARGETS, ITERATIONS, WARMUP_ITERATIONS)
    summary = summarize(samples)
    print_report(summary)
    violations = check_budgets(summary)
    assert not violations, "Estouro de orçamento de latência:\n" + "\n".join(violations)

def test_no_regression_vs_baseline():
    samples = run_samples(TARGETS, ITERATIONS, WARMUP_ITERATIONS)
    summary = summarize(samples)
    regressions = check_regression(summary)
    assert not regressions, "Regressão de performance detectada:\n" + "\n".join(regressions)

if __name__ == "__main__":
    result_samples = run_samples(TARGETS, ITERATIONS, WARMUP_ITERATIONS)
    result_summary = summarize(result_samples)
    print_report(result_summary)

    budget_violations = check_budgets(result_summary)
    if budget_violations:
        print("\nESTOURO DE ORÇAMENTO:")
        for v in budget_violations:
            print(f"  - {v}")

    perf_regressions = check_regression(result_summary)
    if perf_regressions:
        print("\nREGRESSÃO:")
        for r in perf_regressions:
            print(f"  - {r}")

    if "--save-baseline" in sys.argv:
        save_baseline(result_summary)
        print(f"\nBaseline salvo em {REGRESSION_BASELINE}")

    sys.exit(1 if (budget_violations or perf_regressions) else 0)