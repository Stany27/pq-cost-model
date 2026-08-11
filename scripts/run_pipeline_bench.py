"""
Core measurement: one pass of the pipeline over a corpus, timed stage by stage.

Every other script consumes what this one produces. It writes one CSV row per
file, with the latency of each stage separately, so the cost model can be
fitted on per-file data rather than on aggregates.

    python scripts/run_pipeline_bench.py --corpus /mnt/ramdisk/D2 \
           --out results/perfile_D2.csv --config B --kem python

Configurations, matching the ablation in the paper:

    A  zstd + AES + KEM             fixed compressor
    B  raw + AES + KEM              deployable baseline
    C  raw + AES                    classical, prices the post-quantum layer
    D  gzip + AES + KEM             entropy-inappropriate compressor
    E  entropy router + AES + KEM   the configuration the title claims
"""

from __future__ import annotations

import argparse
import csv
import gzip
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from entropy_router import EntropyRouter, Route, shannon_entropy  # noqa: E402
from kdf import derive_aes_key  # noqa: E402

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

CONFIGS = {
    "A": ("zstd",   True),
    "B": ("none",   True),
    "C": ("none",   False),
    "D": ("gzip",   True),
    "E": ("router", True),
}

CHAMPS = [
    "corpus", "config", "kem", "replicate", "seed",
    "file", "extension", "family", "route",
    "size_bytes", "payload_bytes", "cipher_bytes", "entropy_bits_per_byte",
    "t_io_ms", "t_entropy_ms", "t_compress_ms",
    "t_kem_keygen_ms", "t_kem_encaps_ms", "t_kem_decaps_ms", "t_kdf_ms",
    "t_aes_encrypt_ms", "t_aes_decrypt_ms", "t_total_ms",
    "verified", "timestamp",
]


class Kem:
    """Wraps the key-encapsulation mechanism, pure-Python or native."""

    def __init__(self, mode: str):
        self.mode = mode
        if mode == "native":
            try:
                import oqs
            except ImportError:
                sys.exit("\n  liboqs-python is not installed.\n"
                         "  Build liboqs, then: pip install liboqs-python\n"
                         "  Or run with --kem python.\n")
            self.oqs = oqs
        elif mode == "python":
            try:
                from kyber_py.ml_kem import ML_KEM_1024
            except ImportError:
                sys.exit("\n  kyber-py is not installed.\n"
                         "  pip install kyber-py\n")
            self.ml_kem = ML_KEM_1024
        elif mode != "none":
            raise ValueError(mode)

    def exchange(self) -> tuple[bytes, float, float, float]:
        """One complete exchange. Returns the shared secret and three timings."""
        if self.mode == "none":
            return os.urandom(32), 0.0, 0.0, 0.0

        if self.mode == "native":
            with self.oqs.KeyEncapsulation("ML-KEM-1024") as kem:
                t = time.perf_counter(); pk = kem.generate_keypair()
                t_kg = (time.perf_counter() - t) * 1000
                t = time.perf_counter(); ct, ss = kem.encap_secret(pk)
                t_en = (time.perf_counter() - t) * 1000
                t = time.perf_counter(); ss2 = kem.decap_secret(ct)
                t_de = (time.perf_counter() - t) * 1000
            if ss != ss2:
                raise RuntimeError("decapsulation mismatch")
            return ss, t_kg, t_en, t_de

        t = time.perf_counter(); pk, sk = self.ml_kem.keygen()
        t_kg = (time.perf_counter() - t) * 1000
        t = time.perf_counter(); ss, ct = self.ml_kem.encaps(pk)
        t_en = (time.perf_counter() - t) * 1000
        t = time.perf_counter(); ss2 = self.ml_kem.decaps(sk, ct)
        t_de = (time.perf_counter() - t) * 1000
        if ss != ss2:
            raise RuntimeError("decapsulation mismatch")
        return ss, t_kg, t_en, t_de


def compresser(donnees: bytes, mode: str, routeur: EntropyRouter):
    """Apply the configuration's strategy. Returns payload, route, entropy, timings."""
    t = time.perf_counter()
    entropie = None

    if mode == "router":
        decision = routeur.decide_bytes(donnees)
        entropie = decision.entropy
        t_ent = (time.perf_counter() - t) * 1000
        t = time.perf_counter()
        charge, r = routeur.compress(donnees, decision)
        return charge, r.value, entropie, t_ent, (time.perf_counter() - t) * 1000

    t_ent = (time.perf_counter() - t) * 1000
    t = time.perf_counter()
    if mode == "zstd":
        import zstandard as zstd
        charge, route = zstd.ZstdCompressor(level=3).compress(donnees), "zstd"
    elif mode == "gzip":
        charge, route = gzip.compress(donnees, compresslevel=6), "gzip"
    else:
        charge, route = donnees, "none"
    return charge, route, entropie, t_ent, (time.perf_counter() - t) * 1000


def decompresser(charge: bytes, route: str, routeur: EntropyRouter) -> bytes:
    if route == "gzip":
        return gzip.decompress(charge)
    return routeur.decompress(charge, Route(route))


def mesurer(chemin: Path, mode: str, kem: Kem, routeur: EntropyRouter,
            verifier: bool) -> dict:
    depart = time.perf_counter()

    t = time.perf_counter(); donnees = chemin.read_bytes()
    t_io = (time.perf_counter() - t) * 1000

    charge, route, entropie, t_ent, t_comp = compresser(donnees, mode, routeur)
    secret, t_kg, t_en, t_de = kem.exchange()

    t = time.perf_counter(); cle = derive_aes_key(secret)
    t_kdf = (time.perf_counter() - t) * 1000

    aead = AESGCM(cle)
    nonce = os.urandom(12)
    t = time.perf_counter(); chiffre = aead.encrypt(nonce, charge, None)
    t_enc = (time.perf_counter() - t) * 1000

    t_dec, verifie = 0.0, ""
    if verifier:
        t = time.perf_counter(); clair = aead.decrypt(nonce, chiffre, None)
        t_dec = (time.perf_counter() - t) * 1000
        verifie = "ok" if decompresser(clair, route, routeur) == donnees else "MISMATCH"

    if entropie is None:
        entropie = shannon_entropy(donnees[:65536])

    return {
        "file": chemin.name,
        "extension": chemin.suffix.lower() or "(none)",
        "family": "high" if entropie > routeur.threshold else "low",
        "route": route,
        "size_bytes": len(donnees),
        "payload_bytes": len(charge),
        "cipher_bytes": len(chiffre),
        "entropy_bits_per_byte": round(entropie, 4),
        "t_io_ms": round(t_io, 4),
        "t_entropy_ms": round(t_ent, 4),
        "t_compress_ms": round(t_comp, 4),
        "t_kem_keygen_ms": round(t_kg, 4),
        "t_kem_encaps_ms": round(t_en, 4),
        "t_kem_decaps_ms": round(t_de, 4),
        "t_kdf_ms": round(t_kdf, 4),
        "t_aes_encrypt_ms": round(t_enc, 4),
        "t_aes_decrypt_ms": round(t_dec, 4),
        "t_total_ms": round((time.perf_counter() - depart) * 1000, 4),
        "verified": verifie,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--config", default="B", choices=sorted(CONFIGS))
    ap.add_argument("--kem", default="python", choices=("python", "native", "none"))
    ap.add_argument("--replicate", type=int, default=0)
    ap.add_argument("--seed", type=int, default=20260801)
    ap.add_argument("--threshold", type=float, default=7.5)
    ap.add_argument("--verify-every", type=int, default=0,
                    help="verify the round trip on one file out of N; 0 disables")
    args = ap.parse_args()

    racine = Path(args.corpus)
    fichiers = sorted(p for p in racine.rglob("*") if p.is_file())
    if not fichiers:
        sys.exit(f"No files under {racine}")

    mode, avec_kem = CONFIGS[args.config]
    kem = Kem(args.kem if avec_kem else "none")
    routeur = EntropyRouter(threshold=args.threshold)

    sortie = Path(args.out)
    sortie.parent.mkdir(parents=True, exist_ok=True)
    horodatage = time.strftime("%Y-%m-%dT%H:%M:%S")

    print(f"  {racine.name}: {len(fichiers)} files, config {args.config} "
          f"({mode}, kem={kem.mode}), replicate {args.replicate}")

    lignes, octets, echecs = [], 0, 0
    depart = time.perf_counter()

    for i, chemin in enumerate(fichiers, 1):
        verifier = args.verify_every > 0 and i % args.verify_every == 0
        try:
            ligne = mesurer(chemin, mode, kem, routeur, verifier)
        except Exception as e:
            echecs += 1
            print(f"    FAILED on {chemin.name}: {e}")
            continue

        if ligne["verified"] == "MISMATCH":
            echecs += 1
            print(f"    ROUND-TRIP MISMATCH on {chemin.name}")

        ligne.update({"corpus": racine.name, "config": args.config,
                      "kem": kem.mode, "replicate": args.replicate,
                      "seed": args.seed, "timestamp": horodatage})
        lignes.append(ligne)
        octets += ligne["size_bytes"]

        if i % 2000 == 0:
            ecoule = time.perf_counter() - depart
            print(f"    {i:6}/{len(fichiers)}  "
                  f"{octets / 1024**2 / ecoule:7.1f} MB/s", flush=True)

    duree = time.perf_counter() - depart

    with sortie.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CHAMPS)
        w.writeheader()
        w.writerows(lignes)

    debit = octets / 1024 ** 2 / duree if duree else 0
    print(f"\n  {len(lignes)} files, {octets / 1024**3:.2f} GB, "
          f"{duree:.1f} s, {debit:.1f} MB/s")
    if echecs:
        print(f"  {echecs} failure(s) — inspect before using these results.")
    print(f"  -> {sortie}")

    if echecs:
        sys.exit(1)


if __name__ == "__main__":
    main()
