"""
Ablation across five pipeline configurations.

Configuration E is new and it is the one the paper's title claims: rather than
compressing by default or not at all, the router decides per file on measured
entropy. A and D bracket it with fixed choices, B is the deployable baseline,
C removes post-quantum protection to price it.

    python scripts/run_ablation.py --configs A B C D E --replicates 10

One function must be adapted before first use: `encrypt_payload`, marked below.
Everything else is generic.
"""

from __future__ import annotations

import argparse
import gzip
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from entropy_router import EntropyRouter, Route  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

CONFIGS = {
    "A": ("zstd + AES + KEM", "zstd", True),
    "B": ("raw + AES + KEM", "none", True),
    "C": ("raw + AES", "none", False),
    "D": ("gzip + AES + KEM", "gzip", True),
    "E": ("entropy router + AES + KEM", "router", True),
}


# ---------------------------------------------------------------------------
# ADAPT THIS to call your own pipeline. It must perform the key establishment
# (when with_kem is True), the HKDF derivation, and the AES-256-GCM pass, then
# return the ciphertext length. Timing is handled by the caller.
# ---------------------------------------------------------------------------
def encrypt_payload(payload: bytes, with_kem: bool) -> int:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os

    sys.path.insert(0, str(ROOT / "src"))
    from kdf import derive_aes_key

    if with_kem:
        try:
            from kyber_py.ml_kem import ML_KEM_1024      # adapt to your import
        except ImportError:
            sys.exit(
                "\nML-KEM is not available in this environment.\n"
                "  pip install -r env/requirements.txt\n"
                "Or run only the configurations that do not need it:\n"
                "  python scripts/run_ablation.py --configs C\n"
            )
        pk, sk = ML_KEM_1024.keygen()
        shared_secret, ct_key = ML_KEM_1024.encaps(pk)
    else:
        shared_secret = os.urandom(32)                    # classical baseline

    key = derive_aes_key(shared_secret)
    nonce = os.urandom(12)
    return len(AESGCM(key).encrypt(nonce, payload, None))


# ---------------------------------------------------------------------------
def prepare(payload: bytes, mode: str, router: EntropyRouter) -> tuple[bytes, str]:
    """Apply the configuration's compression strategy. Returns payload and label."""
    if mode == "none":
        return payload, "none"

    if mode == "zstd":
        import zstandard as zstd
        return zstd.ZstdCompressor(level=3).compress(payload), "zstd"

    if mode == "gzip":
        return gzip.compress(payload, compresslevel=6), "gzip"

    if mode == "router":
        decision = router.decide_bytes(payload)
        out, route = router.compress(payload, decision)
        return out, route.value

    raise ValueError(f"unknown mode: {mode}")


def run_config(key: str, files: list[Path], router: EntropyRouter) -> dict:
    label, mode, with_kem = CONFIGS[key]
    total_in = total_out = 0
    routes: dict[str, int] = {}
    started = time.perf_counter()

    for path in files:
        data = path.read_bytes()
        payload, route = prepare(data, mode, router)
        routes[route] = routes.get(route, 0) + 1
        total_in += len(data)
        total_out += encrypt_payload(payload, with_kem)

    elapsed = time.perf_counter() - started
    return {
        "config": key,
        "label": label,
        "files": len(files),
        "bytes_in": total_in,
        "bytes_out": total_out,
        "seconds": round(elapsed, 3),
        "throughput_mb_s": round(total_in / (1024 ** 2) / elapsed, 1) if elapsed else 0,
        "volume_ratio": round(total_in / total_out, 3) if total_out else 0,
        "routes": routes,
        "post_quantum": with_kem,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--configs", nargs="+", default=list(CONFIGS))
    ap.add_argument("--corpus", default="/mnt/ramdisk/D1")
    ap.add_argument("--replicates", type=int, default=10)
    ap.add_argument("--warmup", type=int, default=2)
    ap.add_argument("--threshold", type=float, default=7.5)
    ap.add_argument("--out", default=str(RESULTS / "ablation.json"))
    args = ap.parse_args()

    corpus = Path(args.corpus)
    files = sorted(p for p in corpus.rglob("*") if p.is_file())
    if not files:
        sys.exit(f"No files under {corpus}")

    router = EntropyRouter(threshold=args.threshold)
    print(f"{len(files)} files from {corpus}, threshold {args.threshold} bits/byte\n")

    records = []
    for key in args.configs:
        if key not in CONFIGS:
            print(f"  unknown configuration {key}, skipped")
            continue

        for _ in range(args.warmup):
            run_config(key, files, router)          # discarded

        runs = [run_config(key, files, router) for _ in range(args.replicates)]
        tputs = [r["throughput_mb_s"] for r in runs]
        mean = statistics.mean(tputs)
        cv = 100 * statistics.stdev(tputs) / mean if len(tputs) > 1 and mean else 0.0

        summary = {
            **runs[0],
            "replicates": len(runs),
            "throughput_mean_mb_s": round(mean, 1),
            "throughput_stdev_mb_s": round(statistics.stdev(tputs), 1) if len(tputs) > 1 else 0.0,
            "cv_pct": round(cv, 1),
            "accepted": cv < 15.0,
            "all_throughputs": tputs,
        }
        records.append(summary)

        flag = "" if summary["accepted"] else "   CV > 15%, inconclusive"
        print(f"  {key}  {summary['label']:32} "
              f"{mean:7.1f} MB/s  CV {cv:4.1f}%  ratio {summary['volume_ratio']:.3f}{flag}")
        if key == "E":
            print(f"       routing: {summary['routes']}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(records, indent=2))
    print(f"\n-> {out}")

    e = next((r for r in records if r["config"] == "E"), None)
    b = next((r for r in records if r["config"] == "B"), None)
    if e and b:
        gain = 100 * (e["throughput_mean_mb_s"] - b["throughput_mean_mb_s"]) / b["throughput_mean_mb_s"]
        print(f"\nConfiguration E against B: {gain:+.1f}% throughput, "
              f"volume ratio {e['volume_ratio']:.3f} against {b['volume_ratio']:.3f}")
        if gain < 0:
            print("The router costs more than it saves on this corpus. Report that")
            print("as the finding rather than tuning the threshold until it looks good.")


if __name__ == "__main__":
    main()
