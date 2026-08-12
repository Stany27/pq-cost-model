"""
Entropy profile of the corpora.

The pipeline routes each file on a Shannon-entropy threshold. That threshold
must be shown to separate the two content families rather than asserted, since
the paper's title claims the pipeline is entropy-aware.

    python scripts/entropy_profile.py --corpora D1 D2 D3 \
           --out results/entropy_distribution.csv

Produces the CSV and a distribution figure. If the two families do not separate
cleanly, say so in the paper and report the overlap: a threshold that fails to
discriminate is a finding, not a defect to hide.
"""

import argparse
import math
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

DEFAULT_THRESHOLD = 7.5   # bits per byte
SAMPLE_BYTES = 65536


def shannon_entropy(data: bytes) -> float:
    """Entropy in bits per byte. 8.0 means incompressible."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def profile(root: Path, sample_bytes: int):
    rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            with path.open("rb") as fh:
                sample = fh.read(sample_bytes)
        except OSError:
            continue
        rows.append({
            "corpus": root.name,
            "file": path.name,
            "extension": path.suffix.lower() or "(none)",
            "size_bytes": path.stat().st_size,
            "entropy_bits_per_byte": round(shannon_entropy(sample), 4),
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpora", nargs="+", required=True)
    ap.add_argument("--root", default="/mnt/ramdisk")
    ap.add_argument("--out", default="results/entropy_distribution.csv")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--sample-bytes", type=int, default=SAMPLE_BYTES)
    args = ap.parse_args()

    rows = []
    for name in args.corpora:
        path = Path(args.root) / name
        if not path.exists():
            print(f"  skipped, not found: {path}")
            continue
        found = profile(path, args.sample_bytes)
        print(f"  {name}: {len(found)} files")
        rows += found

    if not rows:
        raise SystemExit("No files profiled. Check --root and --corpora.")

    df = pd.DataFrame(rows)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)

    # --- separation check ------------------------------------------------
    high = df[df.entropy_bits_per_byte > args.threshold]
    low = df[df.entropy_bits_per_byte <= args.threshold]
    print(f"\n  threshold {args.threshold} bits/byte")
    print(f"    above (no compression): {len(high):6} files, "
          f"{100 * len(high) / len(df):5.1f}%")
    print(f"    below (compress):       {len(low):6} files, "
          f"{100 * len(low) / len(df):5.1f}%")

    if len(high) and len(low):
        gap = high.entropy_bits_per_byte.min() - low.entropy_bits_per_byte.max()
        if gap > 0:
            print(f"\n  Clean separation: gap of {gap:.3f} bits/byte between families.")
            print("  The threshold is empirically justified.")
        else:
            print(f"\n  Families overlap by {-gap:.3f} bits/byte.")
            print("  Report the overlap in the paper rather than moving the")
            print("  threshold until it looks clean.")

    print("\n  Entropy by extension")
    summary = (df.groupby("extension")["entropy_bits_per_byte"]
                 .agg(["count", "mean", "min", "max"]).round(3))
    print(summary.to_string())

    # --- figure -----------------------------------------------------------
    fig, ax = plt.subplots(figsize=(6.2, 3.6))
    for ext, group in df.groupby("extension"):
        if len(group) >= 3:
            ax.hist(group.entropy_bits_per_byte, bins=40, alpha=0.55, label=ext)
    ax.axvline(args.threshold, color="k", ls="--", lw=1.2,
               label=f"threshold {args.threshold}")
    ax.set_xlabel("Shannon entropy (bits per byte)")
    ax.set_ylabel("Files")
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(out.with_name("fig_entropy_distribution.pdf"))

    print(f"\n-> {out}")
    print(f"-> {out.with_name('fig_entropy_distribution.pdf')}")


if __name__ == "__main__":
    main()
