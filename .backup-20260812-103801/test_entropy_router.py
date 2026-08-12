"""
Tests for the entropy router.

Checks the four properties the paper's claims depend on: that high-entropy
content bypasses compression, that low-entropy content does not, that the
round trip is lossless, and that a compressor which expands its input is
refused.

    python scripts/test_entropy_router.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from entropy_router import (  # noqa: E402
    EntropyRouter, Route, shannon_entropy, DEFAULT_THRESHOLD,
)

failures = []


def check(name, condition):
    print(f"  {'PASS' if condition else 'FAIL'}  {name}")
    if not condition:
        failures.append(name)


router = EntropyRouter()

# --- the entropy measure itself -------------------------------------------
print("Entropy measure")
check("empty input gives 0", shannon_entropy(b"") == 0.0)
check("a single repeated byte gives 0", shannon_entropy(b"\x00" * 4096) == 0.0)
check("random bytes approach 8", shannon_entropy(os.urandom(65536)) > 7.9)
check("English-like text sits well below 8",
      shannon_entropy(b"the quick brown fox " * 500) < 5.0)

# --- routing decisions ------------------------------------------------------
print("\nRouting")
random_payload = os.urandom(200_000)
text_payload = (b"timestamp,level,message\n"
                b"2026-08-09T12:00:00Z,INFO,request served\n") * 4000

d_random = router.decide_bytes(random_payload)
d_text = router.decide_bytes(text_payload)

check("high-entropy content bypasses compression", d_random.route is Route.NONE)
check("low-entropy content routes to zstd", d_text.route is Route.ZSTD)
check("the decision records its entropy", d_random.entropy > DEFAULT_THRESHOLD)
check("the decision records a reason", bool(d_text.reason))
check("tiny files are not routed",
      router.decide_bytes(b"short").route is Route.NONE)

# --- round trip -------------------------------------------------------------
print("\nRound trip")
try:
    payload, route = router.compress(text_payload, d_text)
    check("compression actually reduces low-entropy content",
          len(payload) < len(text_payload))
    check("round trip is lossless",
          router.decompress(payload, route) == text_payload)

    payload2, route2 = router.compress(random_payload, d_random)
    check("high-entropy content passes through untouched",
          payload2 == random_payload and route2 is Route.NONE)
    check("round trip on the bypass path is lossless",
          router.decompress(payload2, route2) == random_payload)
except ImportError:
    print("  SKIP  zstandard not installed; run pip install -r env/requirements.txt")

# --- refusing a losing compressor ------------------------------------------
print("\nGuard against expansion")
try:
    incompressible = os.urandom(100_000)
    forced = router.decide_bytes(incompressible)
    # Force the zstd path even though the router would bypass it
    from entropy_router import Decision
    forced = Decision(Route.ZSTD, 0.0, 0, len(incompressible), "forced for test")
    out, route = router.compress(incompressible, forced)
    check("expansion is refused and the payload passes through",
          route is Route.NONE and out == incompressible)
except ImportError:
    print("  SKIP  zstandard not installed")

# --- input validation -------------------------------------------------------
print("\nInput validation")
for bad in (-1.0, 0.0, 8.0, 9.5):
    try:
        EntropyRouter(threshold=bad)
        check(f"threshold {bad} rejected", False)
        break
    except ValueError:
        pass
else:
    check("out-of-range thresholds rejected", True)

print()
if failures:
    print(f"{len(failures)} test(s) failed.")
    sys.exit(1)
print("All tests passed.")
