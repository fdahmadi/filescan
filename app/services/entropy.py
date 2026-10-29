from pathlib import Path
from collections import Counter
import math


def shannon_entropy(path: Path, sample_bytes: int = 256 * 1024) -> float | None:
    """Approximate Shannon entropy (0..8) from up to sample_bytes of the file."""
    try:
        data = path.read_bytes()[:sample_bytes]
    except OSError:
        return None
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
