"""
Entropy-aware routing.

The pipeline's distinguishing feature, and the one its title claims: rather than
compressing every input by default, each file is routed on a measurement of its
content entropy.

The rule is simple and the justification is empirical. Already-compressed
content sits near 8 bits per byte and cannot be reduced further; applying a
compressor to it costs throughput and returns nothing. Text, logs and tabular
data sit well below and compress cheaply. The threshold separating them is not
assumed here: scripts/entropy_profile.py measures it on the corpora and reports
whether the two families actually separate.

References for the measure: Shannon (1948). The sampling strategy follows common
practice in file-type detection, where a leading window is representative enough
for a first-order entropy estimate.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Route(str, Enum):
    """Where the router sends a file."""
    NONE = "none"      # straight to AEAD, no compression
    ZSTD = "zstd"      # classical lossless, low-entropy content
    LEARNED = "learned"  # reserved; not enabled, see the paper


# Bits per byte. Content above this is treated as incompressible.
# Justify this value from results/entropy_distribution.csv before publishing;
# do not move it until the separation looks clean.
DEFAULT_THRESHOLD = 7.5

# Reading the whole file to decide would defeat the purpose. A leading window
# is enough for a first-order estimate and costs a single seek.
DEFAULT_SAMPLE_BYTES = 65_536

# Below this size the routing decision cannot pay for itself: the per-file KEM
# cost dominates so heavily that compression is irrelevant either way.
MIN_SIZE_TO_CONSIDER = 4_096


@dataclass(frozen=True)
class Decision:
    """What the router decided, and why. Kept for the audit trail."""
    route: Route
    entropy: float
    sampled_bytes: int
    file_size: int
    reason: str


def shannon_entropy(data: bytes) -> float:
    """
    First-order Shannon entropy in bits per byte.

    Returns 0.0 for empty input and approaches 8.0 for uniformly random bytes.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class EntropyRouter:
    """
    Routes files to a compression strategy based on measured entropy.

    The router carries no cryptographic property. It decides only whether
    compressing before encryption is worth the throughput it costs.
    """

    def __init__(
        self,
        threshold: float = DEFAULT_THRESHOLD,
        sample_bytes: int = DEFAULT_SAMPLE_BYTES,
        min_size: int = MIN_SIZE_TO_CONSIDER,
    ) -> None:
        if not 0.0 < threshold < 8.0:
            raise ValueError("threshold must lie strictly between 0 and 8 bits/byte")
        self.threshold = threshold
        self.sample_bytes = sample_bytes
        self.min_size = min_size

    # ------------------------------------------------------------------
    def decide_bytes(self, data: bytes, declared_size: int | None = None) -> Decision:
        """Route an in-memory payload."""
        size = declared_size if declared_size is not None else len(data)

        if size < self.min_size:
            return Decision(Route.NONE, 0.0, 0, size,
                            f"below {self.min_size} B; routing cannot pay for itself")

        sample = data[: self.sample_bytes]
        h = shannon_entropy(sample)

        if h > self.threshold:
            return Decision(Route.NONE, h, len(sample), size,
                            f"entropy {h:.3f} > {self.threshold}; already compressed")
        return Decision(Route.ZSTD, h, len(sample), size,
                        f"entropy {h:.3f} <= {self.threshold}; compressible")

    def decide_path(self, path: str | Path) -> Decision:
        """Route a file on disk, reading only the leading window."""
        p = Path(path)
        size = p.stat().st_size
        if size < self.min_size:
            return Decision(Route.NONE, 0.0, 0, size,
                            f"below {self.min_size} B; routing cannot pay for itself")
        with p.open("rb") as fh:
            sample = fh.read(self.sample_bytes)
        return self.decide_bytes(sample, declared_size=size)

    # ------------------------------------------------------------------
    def compress(self, data: bytes, decision: Decision) -> tuple[bytes, Route]:
        """
        Apply the decided strategy.

        Returns the payload to hand to AES-GCM and the route actually taken.
        If compression expands the data, the router falls back to NONE: a
        compressor that grows its input is worse than no compressor at all.
        """
        if decision.route is Route.NONE:
            return data, Route.NONE

        if decision.route is Route.ZSTD:
            import zstandard as zstd
            out = zstd.ZstdCompressor(level=3).compress(data)
            if len(out) >= len(data):
                return data, Route.NONE
            return out, Route.ZSTD

        raise NotImplementedError(
            "The learned route is not enabled. Section 5.5 of the paper reports "
            "why: reconstruction quality is far below what any downstream use "
            "requires."
        )

    def decompress(self, data: bytes, route: Route) -> bytes:
        """Reverse the applied strategy. The route must be stored with the payload."""
        if route is Route.NONE:
            return data
        if route is Route.ZSTD:
            import zstandard as zstd
            return zstd.ZstdDecompressor().decompress(data)
        raise NotImplementedError("The learned route is not enabled.")
