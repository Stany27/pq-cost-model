"""
Tests for the key derivation step.

    python scripts/test_kdf.py

These are not cryptographic conformance tests. They check the three properties
the security argument relies on: determinism, domain separation, and rejection
of malformed input.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from kdf import derive_aes_key, derive_multiple, INFO_AES_GCM  # noqa: E402

failures = []


def check(name, condition):
    print(f"  {'PASS' if condition else 'FAIL'}  {name}")
    if not condition:
        failures.append(name)


secret = bytes(range(32))

print("Key derivation")
check("output is 32 bytes",
      len(derive_aes_key(secret)) == 32)

check("derivation is deterministic",
      derive_aes_key(secret) == derive_aes_key(secret))

check("distinct secrets give distinct keys",
      derive_aes_key(secret) != derive_aes_key(os.urandom(32)))

check("distinct labels give distinct keys",
      derive_aes_key(secret, b"label-a") != derive_aes_key(secret, b"label-b"))

check("derived key differs from the shared secret",
      derive_aes_key(secret) != secret)

print("\nInput validation")
try:
    derive_aes_key(b"too short")
    check("short input rejected", False)
except ValueError:
    check("short input rejected", True)

try:
    derive_aes_key("not bytes")
    check("wrong type rejected", False)
except TypeError:
    check("wrong type rejected", True)

print("\nDomain separation across uses")
keys = derive_multiple(secret, {
    "data": b"pq-pipeline|v1|AES-256-GCM|data-encryption-key",
    "meta": b"pq-pipeline|v1|AES-256-GCM|metadata-encryption-key",
})
check("two labels yield two different keys",
      keys["data"] != keys["meta"])

print()
if failures:
    print(f"{len(failures)} test(s) failed.")
    sys.exit(1)
print("All tests passed.")
