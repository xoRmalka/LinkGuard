import math
import re
from collections import Counter


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def entropy_signal(path_query: str) -> dict:
    """High entropy in path/query can indicate machine-generated phishing paths."""
    sample = path_query or ""
    score = shannon_entropy(sample)
    # Typical human-readable paths: ~3–4.5; long random tokens often >4.5
    concern = score >= 4.6 and len(sample) >= 24
    return {
        "id": "entropy",
        "status": "ok",
        "value": round(score, 3),
        "concern": concern,
        "summary": "Path and query look unusually random." if concern else "Path entropy looks typical.",
    }
