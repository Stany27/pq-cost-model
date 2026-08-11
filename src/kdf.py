"""
Key derivation for the hybrid pipeline.

ML-KEM.Encaps returns a 32-byte shared secret. Rather than using that secret
directly as the AES-256-GCM key, we derive the working key with HKDF-SHA-256
under an explicit info label. This makes assumption (H3) of the security
argument true as implemented, and it leaves room for a second key to be derived
from the same secret later without domain collision.

The cost is negligible: HKDF-SHA-256 over a 32-byte input runs in a few
microseconds, against roughly 43 ms for the key encapsulation it follows.

Reference: RFC 5869; NIST SP 800-56C Rev. 2 for key derivation following a
key-establishment scheme.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# The label binds the derived key to one algorithm, one purpose and one version.
# Changing any of these three must change the label, otherwise two different
# uses could end up sharing a key.
INFO_AES_GCM = b"pq-pipeline|v1|AES-256-GCM|data-encryption-key"

SHARED_SECRET_LEN = 32   # ML-KEM-1024, per FIPS 203
AES_KEY_LEN = 32         # AES-256


def derive_aes_key(shared_secret: bytes, info: bytes = INFO_AES_GCM) -> bytes:
    """
    Derive the AES-256-GCM session key from the ML-KEM shared secret.

    salt is None, which HKDF treats as a string of zeros of the hash length.
    That is correct here: the input keying material is already uniformly
    distributed, so the extract step needs no additional entropy, and a fixed
    salt keeps the derivation deterministic and reproducible across runs.
    """
    if not isinstance(shared_secret, (bytes, bytearray)):
        raise TypeError("shared_secret must be bytes")
    if len(shared_secret) != SHARED_SECRET_LEN:
        raise ValueError(
            f"expected a {SHARED_SECRET_LEN}-byte shared secret, "
            f"got {len(shared_secret)}"
        )

    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LEN,
        salt=None,
        info=info,
    ).derive(bytes(shared_secret))


def derive_multiple(shared_secret: bytes, labels: dict[str, bytes]) -> dict[str, bytes]:
    """
    Derive several independent keys from one shared secret.

    Not used by the pipeline as measured, but included because it is the reason
    the derivation step exists: without domain separation, adding a second use
    for the same secret would be unsafe.
    """
    return {name: derive_aes_key(shared_secret, info) for name, info in labels.items()}
