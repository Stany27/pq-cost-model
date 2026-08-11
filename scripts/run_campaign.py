"""
Measurement campaign runner.

Enforces the protocol: warm-up runs discarded, replicates in randomised order,
page cache dropped between replicates, environment state recorded alongside
every measurement.

    python scripts/run_campaign.py --corpora D1 D2 --replicates 10 --warmup 2

One line must be adapted before first use: the command that invokes your own
benchmark script. It is marked BENCHMARK_CMD below.
"""

import argparse
import json
import platform
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results" / "campaign"

# --------------------------------------------------------------------------
# ADAPT THIS to your own benchmark entry point. It must accept a corpus path
# and an output CSV path, and write one row per file.
# --------------------------------------------------------------------------
BENCHMARK_CMD = [sys.executable, str(ROOT / "scripts" / "run_pipeline_bench.py")]

CV_THRESHOLD = 15.0   # per cent; announced in advance, see the protocol


def drop_caches():
    """Flush the page cache. Silently skipped where unavailable."""
    if platform.system() == "Linux":
        try:
            subprocess.run(["sync"], check=True)
            subprocess.run(
                ["sudo", "tee", "/proc/sys/vm/drop_caches"],
                input=b"3", stdout=subprocess.DEVNULL, check=True,
            )
            return "dropped"
        except (subprocess.CalledProcessError, FileNotFoundError):
            return "failed"
    return "unavailable"


def machine_state():
    """Record what the host was doing, so an outlier can be explained later."""
    state = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }
    try:
        import psutil
        state["cpu_percent"] = psutil.cpu_percent(interval=1.0)
        state["mem_available_gb"] = round(psutil.virtual_memory().available / 2**30, 2)
        temps = getattr(psutil, "sensors_temperatures", lambda: {})()
        if temps:
            first = next(iter(temps.values()))
            if first:
                state["cpu_temp_c"] = first[0].current
    except Exception:
        state["cpu_percent"] = None
    return state


def run_one(corpus, corpus_path, replicate, out_csv):
    cache = drop_caches()
    before = machine_state()

    started = time.perf_counter()
    proc = subprocess.run(
        BENCHMARK_CMD + ["--corpus", str(corpus_path), "--out", str(out_csv),
         "--replicate", str(replicate), "--verify-every", "100"],
        capture_output=True, text=True,
    )
    elapsed = time.perf_counter() - started

    if proc.returncode != 0:
        print(f"    FAILED: {proc.stderr.strip()[:200]}")
        return None

    return {
        "corpus": corpus,
        "replicate": replicate,
        "wall_seconds": round(elapsed, 3),
        "cache": cache,
        "csv": out_csv.name,
        **before,
    }


def aggregate(records):
    """Coefficient of variation of wall time, per corpus."""
    import statistics
    out = {}
    for corpus in sorted({r["corpus"] for r in records}):
        times = [r["wall_seconds"] for r in records if r["corpus"] == corpus]
        if len(times) < 2:
            continue
        mean = statistics.mean(times)
        cv = 100 * statistics.stdev(times) / mean if mean else float("inf")
        out[corpus] = {
            "n": len(times),
            "mean_s": round(mean, 2),
            "stdev_s": round(statistics.stdev(times), 2),
            "cv_pct": round(cv, 1),
            "min_s": round(min(times), 2),
            "max_s": round(max(times), 2),
            "spread_ratio": round(max(times) / min(times), 1),
            "accepted": cv < CV_THRESHOLD,
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpora", nargs="+", default=["D1", "D2", "D3"])
    ap.add_argument("--replicates", type=int, default=10)
    ap.add_argument("--warmup", type=int, default=2)
    ap.add_argument("--root", default="/mnt/ramdisk",
                    help="where the corpora live; use R:\\ on Windows")
    ap.add_argument("--seed", type=int, default=20260801)
    args = ap.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    corpus_root = Path(args.root)

    missing = [c for c in args.corpora if not (corpus_root / c).exists()]
    if missing:
        sys.exit(f"Corpora not found under {corpus_root}: {missing}")

    free_gb = shutil.disk_usage(RESULTS).free / 2**30
    print(f"Output space available: {free_gb:.1f} GB\n")

    # --- warm-up, discarded ------------------------------------------------
    print(f"Warm-up: {args.warmup} run(s) per corpus, discarded")
    for corpus in args.corpora:
        for i in range(args.warmup):
            print(f"  {corpus} warm-up {i + 1}/{args.warmup}")
            run_one(corpus, corpus_root / corpus, -1,
                    RESULTS / f"warmup_{corpus}_{i}.csv")

    # --- measured replicates, randomised order -----------------------------
    plan = [(c, r) for c in args.corpora for r in range(args.replicates)]
    random.Random(args.seed).shuffle(plan)

    print(f"\nCampaign: {len(plan)} runs in randomised order (seed {args.seed})\n")
    records = []
    for n, (corpus, rep) in enumerate(plan, 1):
        print(f"  [{n:3}/{len(plan)}] {corpus} replicate {rep}")
        rec = run_one(corpus, corpus_root / corpus, rep,
                      RESULTS / f"{corpus}_rep{rep:02d}.csv")
        if rec:
            records.append(rec)
            (RESULTS / "campaign_log.json").write_text(json.dumps(records, indent=2))

    # --- acceptance check ---------------------------------------------------
    summary = aggregate(records)
    (RESULTS / "campaign_summary.json").write_text(json.dumps(summary, indent=2))

    print("\n" + "=" * 62)
    print(f"{'Corpus':8} {'n':>3} {'mean(s)':>9} {'CV%':>7} {'spread':>8}  verdict")
    print("-" * 62)
    for corpus, s in summary.items():
        verdict = "accepted" if s["accepted"] else "INCONCLUSIVE"
        print(f"{corpus:8} {s['n']:3} {s['mean_s']:9.2f} {s['cv_pct']:7.1f} "
              f"{s['spread_ratio']:7.1f}x  {verdict}")
    print("=" * 62)

    rejected = [c for c, s in summary.items() if not s["accepted"]]
    if rejected:
        print(f"\nCV exceeds {CV_THRESHOLD}% for: {', '.join(rejected)}.")
        print("Per the protocol, report these as inconclusive rather than")
        print("defending the absolute figures. Check that the corpus is in RAM,")
        print("that background services are stopped, and that no interactive")
        print("session is open.")
        sys.exit(2)

    print("\nAll configurations meet the acceptance criterion.")


if __name__ == "__main__":
    main()
