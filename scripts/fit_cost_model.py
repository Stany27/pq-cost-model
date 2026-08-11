"""
Fit of the per-object cost model on per-file measurements.

Model:   t_i = t_KEM + S_i * kappa,   with kappa = 1/T_AES + 1/T_IO

kappa is calibrated on D2 alone -- the corpus whose file-size distribution is
narrowest, so its mean is a reasonable stand-in for its median -- then applied
unchanged to D1 and D3. This makes Table 7 an out-of-sample check rather than an
arithmetic restatement of Table 6.

Produces:
    results/cost_model_fit.csv       Table 7 of the article
    results/fig_cost_model_fit.pdf   predicted against measured per-file latency
    results/fig_crossover.pdf        crossover size S* against t_KEM

Usage:
    python scripts/fit_cost_model.py
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

RESULTS = Path(__file__).resolve().parent.parent / "results"

# --------------------------------------------------------------------------
# ADAPT THESE to the actual column names in your CSV files, then delete this
# comment. Run once and check that kappa comes out near 2.2 ms/MB; if it does
# not, the mapping below is wrong.
# --------------------------------------------------------------------------
FILES = {"D1": "perfile_D1.csv", "D2": "perfile_D2.csv", "D3": "perfile_D3.csv"}
COL_SIZE = "file_size_bytes"
COL_KEM = "t_kem_ms"
COL_AES = "t_aes_ms"
COL_IO = "t_io_ms"

T_AES_PEAK = 1946.0  # MB/s, Table 2, 256 KB payload


def load(name):
    path = RESULTS / FILES[name]
    if not path.exists():
        sys.exit(f"Missing: {path}\nAdapt FILES/COL_* at the top of this script.")
    df = pd.read_csv(path)
    missing = [c for c in (COL_SIZE, COL_KEM, COL_AES, COL_IO) if c not in df.columns]
    if missing:
        sys.exit(f"{path.name}: columns not found: {missing}\n"
                 f"Available: {list(df.columns)}")
    df["size_mb"] = df[COL_SIZE] / (1024 ** 2)
    df["t_size"] = df[COL_AES] + df[COL_IO]
    return df


def calibrate(df):
    """Least squares through the origin: t_size = kappa * S."""
    s, t = df["size_mb"].to_numpy(), df["t_size"].to_numpy()
    return float(np.sum(s * t) / np.sum(s ** 2))


def main():
    kappa = calibrate(load("D2"))
    print(f"kappa calibrated on D2: {kappa:.3f} ms/MB "
          f"({1000 / kappa:.0f} MB/s combined AES + I/O)\n")

    rows = []
    fig, ax = plt.subplots(figsize=(5.2, 5.0))

    for name in ("D1", "D2", "D3"):
        df = load(name)
        t_kem = df[COL_KEM].median()
        s_med = df["size_mb"].median()

        phi_pred = 100 * t_kem / (t_kem + s_med * kappa)
        total = (df[COL_KEM] + df[COL_AES] + df[COL_IO]).sum()
        phi_meas = 100 * df[COL_KEM].sum() / total

        rows.append({
            "corpus": name,
            "n_files": len(df),
            "median_size_mb": round(s_med, 2),
            "mean_size_mb": round(df["size_mb"].mean(), 2),
            "t_kem_median_ms": round(t_kem, 2),
            "phi_predicted_pct": round(phi_pred, 1),
            "phi_measured_pct": round(phi_meas, 1),
            "deviation_pt": round(abs(phi_pred - phi_meas), 1),
        })

        t_pred = t_kem + df["size_mb"] * kappa
        t_meas = df[COL_KEM] + df["t_size"]
        ax.scatter(t_pred, t_meas, s=7, alpha=0.3, label=name)

    out = pd.DataFrame(rows)
    print(out.to_string(index=False))
    out.to_csv(RESULTS / "cost_model_fit.csv", index=False)

    hi = max(ax.get_xlim()[1], ax.get_ylim()[1])
    ax.plot([0, hi], [0, hi], "k--", lw=1, label="identity")
    ax.set_xlabel("Predicted per-file latency (ms)")
    ax.set_ylabel("Measured per-file latency (ms)")
    ax.set_xlim(0, hi)
    ax.set_ylim(0, hi)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(RESULTS / "fig_cost_model_fit.pdf")

    # --- crossover S* against t_KEM -------------------------------------
    fig2, ax2 = plt.subplots(figsize=(5.2, 3.6))
    t = np.logspace(-2, 2, 200)              # ms
    ax2.loglog(t, t / 1000 * T_AES_PEAK, "k-", lw=1.2)
    for tk, lab in [(42.9, "pure-Python\n(this work)"),
                    (0.100, "native, 100 us"),
                    (0.050, "native, 50 us")]:
        ax2.plot(tk, tk / 1000 * T_AES_PEAK, "o", ms=6)
        ax2.annotate(lab, (tk, tk / 1000 * T_AES_PEAK),
                     textcoords="offset points", xytext=(6, -12), fontsize=8)
    ax2.set_xlabel(r"$t_{\mathrm{KEM}}$ (ms)")
    ax2.set_ylabel(r"crossover size $S^{*}$ (MB)")
    ax2.grid(True, which="both", ls=":", lw=0.4)
    fig2.tight_layout()
    fig2.savefig(RESULTS / "fig_crossover.pdf")

    print("\n-> results/cost_model_fit.csv")
    print("-> results/fig_cost_model_fit.pdf")
    print("-> results/fig_crossover.pdf")


if __name__ == "__main__":
    main()
