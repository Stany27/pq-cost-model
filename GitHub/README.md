# pq-cost-model

Reproducibility package for **"An Entropy-Aware Post-Quantum Security Pipeline for
Heterogeneous Data Using AES-256-GCM and ML-KEM-1024"**.

## Research objective

Measure, rather than assume, whether routing files to a compressor based on
sampled Shannon entropy is worth its cost once AES-256-GCM and a per-file
ML-KEM-1024 (FIPS 203) key exchange are already part of the pipeline, and
characterise what governs end-to-end throughput on a KEM-per-object
architecture across datasets that differ by orders of magnitude in file
count and cumulative volume.

## Main contribution

- An entropy-aware router (`src/entropy_router.py`) that decides, per file,
  whether to apply zstd compression or pass the file straight to AES-256-GCM,
  based on a windowed Shannon-entropy sample rather than a leading-byte read.
- A reproducible, replicated (10 runs, 2 discarded warm-ups, randomised order,
  pre-registered 15% CV acceptance threshold) measurement campaign across
  three corpora spanning 0.98-43.36 GB and 835-23,785 files, on a dedicated
  Vultr cloud host.
- A negative result, reported as such: the router costs 7.6% throughput on
  D1 and 22.8% on D3 relative to a no-compression baseline, and does not
  reduce output volume below a fixed-zstd baseline on D3.
- A per-file cost model (`t = t_KEM + S*kappa`) fitted on one corpus and
  validated out of sample on the other two, showing that ML-KEM-1024's fixed
  per-file cost (~17.2 ms under this implementation), not byte volume,
  governs throughput.

## Architecture

```
file --> [entropy router: sample, threshold=7.5 bits/byte] --> {none | zstd}
      --> AES-256-GCM authenticated encryption (session key = HKDF-SHA-256(shared secret))
      --> ML-KEM-1024 encapsulation of the session key
```

See Section 4 of the manuscript (`manuscript/manuscript.docx`) for the full
specification, threat model, and security argument.

## Experimental setup

| Element | Value |
|---|---|
| Host | Vultr `vhf-8c-32gb`, Amsterdam |
| CPU | Intel Skylake (IBRS, no TSX), 4 cores / 8 threads, QEMU/KVM |
| RAM | 31 GiB |
| Python | 3.13.7 |
| Seed | `20260801` (corpus generation and replicate ordering) |

## Datasets / corpora

| Corpus | Files | Volume | Composition | Redistributed? |
|---|---|---|---|---|
| D1 | 6,925 | 0.98 GB | source code, docs, minority images/media | No — manifest only (`results/manifests/D1_sha256.txt`) |
| D2 | 23,785 | 16.22 GB | logs, pcaps, csv, json, bin (synthetic) | Regenerate with `build_corpus.py` |
| D3 | 835 | 43.36 GB | bin, mp4, sql, csv (synthetic) | Regenerate with `build_corpus.py` |

D1 is real content assembled by the authors and is not the authors' to
publish in bulk. D2 and D3 are procedurally generated and fully specified by
`config/corpus.json` and the fixed seed; they are not claimed to represent
any specific real-world file population.

## Installation

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python scripts/verify_env.py
```

`scripts/verify_env.py` checks every pinned package version against the
manifest used for the published measurements and exits non-zero on a
mismatch. **Known issue:** the pinned-package check in `verify_env.py`
currently still lists `torch==2.5.1`, a dependency of a previous,
now-removed learned-compression (VAE) branch of this pipeline. It is not
imported anywhere in `src/` or `scripts/` and is not in `requirements.txt`.
Until this is cleaned up, either install `torch` solely to satisfy the
check or delete the `"torch"` line from the `PINNED` dict in
`scripts/verify_env.py` before running it — the entropy-router pipeline
does not require it.

## Environment

See `requirements.txt` for exact pinned versions (`cryptography`, `kyber-py`,
`zstandard`, `numpy`, `pandas`, `scipy`, `statsmodels`, `matplotlib`,
`scikit-image`). An `environment.yml` is also provided for `conda`/`mamba`
users. Native ML-KEM (`liboqs-python`) is optional; without it, only the
pure-Python `kyber-py` shim is measured, which bounds ML-KEM latency figures
from above by roughly one to two orders of magnitude relative to a native
implementation (see Section 7.4 / Section 9 of the manuscript).

## Tests

```bash
python scripts/test_kdf.py
python scripts/test_entropy_router.py
```

## Corpora

```bash
python scripts/build_corpus.py --corpus D2 --out <path> --seed 20260801
python scripts/build_corpus.py --corpus D3 --out <path> --seed 20260801
python scripts/make_manifest.py --corpus <path-to-D1> --out results/manifests/D1_sha256.txt
```

## Benchmark commands

```bash
# Entropy profile and threshold-separation check (Fig. 2 / Table 4)
python scripts/entropy_profile.py --corpora D1 D2 D3 --out results/entropy_distribution.csv

# Per-file pipeline benchmark, one config/corpus at a time (Tables 3-7, cost model)
python scripts/run_pipeline_bench.py --corpus <path-to-D1> --out results/perfile_D1.csv \
       --config B --kem python --verify-every 100

# Ablation across configurations A-E (Table 9, Fig. 5)
python scripts/run_ablation.py --configs A B C D E --corpus <path> --replicates 10

# Weak-scaling campaign, replicated with warm-up and randomised order (Table 11)
python scripts/run_campaign.py --corpora D1 D2 D3 --replicates 10 --root <path>

# Cost-model fit and crossover analysis (Table 10, Figs. 7-8)
python scripts/fit_cost_model.py
```

## Expected outputs

`results/perfile_{D1,D2,D3}.csv` (per-file measurements), `results/entropy_D1.csv`
(entropy profile), `results/ablation*.log` and `results/ablation.json`
(ablation study — note: `ablation.json` is overwritten on every invocation of
`run_ablation.py`; the `.log` files are the durable per-corpus record),
`results/campaign_D1.log` / `results/campaign_D2D3.log` (weak-scaling
summary), `results/cost_model_fit.csv`, `results/fig_cost_model_fit.pdf`,
`results/fig_crossover.pdf`.

## Reproducibility instructions

1. `python scripts/verify_env.py` (see the known-issue note above).
2. Regenerate D2 and D3 with the fixed seed; assemble a matching D1 and
   verify it against `results/manifests/D1_sha256.txt`.
3. Re-run the benchmark and ablation commands above; compare against the
   released CSV/log/JSON files with the same file names.
4. Every numeric claim in Sections 6-7 of the manuscript cites the specific
   released file it was computed from — see `manuscript/manuscript.docx`
   Section 8 (Reproducibility and Open Science) and
   `manuscript/supplementary_material.docx` for the complete accounting.

## Results

Headline results (see the manuscript for the complete set with confidence
statements and limitations):

- Ablation (router vs. no-compression baseline): **-7.6%** throughput on D1,
  **-22.8%** on D3 — a negative result, reported as such.
- Cost model: ML-KEM's per-file cost share predicted to within **2.8
  percentage points** out of sample.
- End-to-end throughput spans **~7 to ~600 MB/s** across corpora and tracks
  file count, not byte volume.
- Primitive-level validation: **775/775** NIST CAVP-style test vectors
  passed (AES-256-GCM and ML-KEM-1024 implementations; does not cover the
  router or the pipeline composition — see Section 6.4 of the manuscript).

## Figures

`manuscript/figures/` contains the nine figures cited in the manuscript, as
both `.png` and `.pdf`: architecture, entropy separation, AES-256-GCM
microbenchmark, ML-KEM parameter comparison, ablation study, latency
breakdown, cost-model fit, crossover analysis, and strong scaling.
Regenerate them with `manuscript/figures/generate_figures_1.py`,
`manuscript/figures/generate_figures_2.py`, and
`manuscript/figures/generate_figure_architecture.py`. Fig. 1 (the
architecture diagram) is also released as an editable
`manuscript/figures/fig_architecture.drawio` source
(open at https://app.diagrams.net), for anyone who wants to restyle it by
hand rather than regenerate it from Python.

## Citation

See `CITATION.cff`. Please cite the paper, not only this repository, when
referencing the results.

## License

Code: to be specified by the authors before publication (e.g. MIT or
Apache-2.0) — no license file is currently present in this repository;
add one before making the repository public if it is not already.

## Ethics / data availability

No human subjects or personal data. D1 is a real corpus of source code,
documentation, and media assembled by the authors and containing no
personal or institutional confidential data; it is not redistributed in
bulk, only as a SHA-256 manifest. D2 and D3 are fully synthetic and
regenerable from the released seed and builder script. No API keys,
credentials, or Vultr access tokens are present in this repository or
should ever be committed to it.
