from collections import defaultdict

def build_index(domains: list) -> dict:
    by_len = defaultdict(list)

    for d in domains:
        if d:
            by_len[len(d)].append(d)

    return by_len