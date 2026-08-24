import statistics
import threading
from concurrent.futures import ThreadPoolExecutor
from time import perf_counter
from providers.rdap.fetch_rdap import fetch_rdap, clear_cache
HOSTS = [
    "google.com", "wikipedia.org", "registro.br", "github.io",
    "example.co", "info.info", "biz.biz", "nic.us", "bbc.uk",
]


def bench_sequential(hosts: list[str], rounds: int = 20) -> list[float]:
    """Mede latência por chamada, sequencial, com cache já quente."""
    clear_cache()
    for h in hosts:
        fetch_rdap(h)
    clear_cache() 

    timings = []
    for _ in range(rounds):
        for h in hosts:
            clear_cache() 
            start = perf_counter()
            fetch_rdap(h)
            timings.append(perf_counter() - start)
    return timings

def bench_concurrent(hosts: list[str], workers: int = 20, repeats: int = 5) -> list[float]:
    timings = []
    timings_lock = threading.Lock()

    def worker(host: str):
        start = perf_counter()
        fetch_rdap(host)
        elapsed = perf_counter() - start
        with timings_lock:
            timings.append(elapsed)

    batch = hosts * repeats
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(lambda h: (clear_cache(), worker(h)), h) for h in batch]
        for f in futures:
            f.result()

    return timings

def report(label: str, timings: list[float]) -> None:
    timings_sorted = sorted(timings)
    p50 = statistics.median(timings_sorted)
    p95 = timings_sorted[int(len(timings_sorted) * 0.95) - 1]
    print(f"\n--- {label} ---")
    print(f"n={len(timings)}  min={min(timings):.4f}s  "
          f"p50={p50:.4f}s  p95={p95:.4f}s  max={max(timings):.4f}s")

if __name__ == "__main__":
    seq = bench_sequential(HOSTS, rounds=5)
    report("sequential (cache miss forçado)", seq)

    conc = bench_concurrent(HOSTS, workers=20)
    report("concurrent (20 workers, TLDs mistos)", conc)