from collections import defaultdict


def build_index(domains):
    by_len = defaultdict(list)
    deletions = defaultdict(list)
    exact = set()
    for item in domains:
        word = item.strip().casefold()
        if not word or word in exact:
            continue
        exact.add(word)
        by_len[len(word)].append(word)
        if 6 <= len(word) <= 63:
            for candidate in {word[:i] + word[i + 1 :] for i in range(len(word))}:
                deletions[candidate].append(word)
    result = dict(by_len)
    result["_exact"] = frozenset(exact)
    result["_deletions"] = dict(deletions)
    return result
