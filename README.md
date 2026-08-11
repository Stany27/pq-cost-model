# An Entropy-Aware Post-Quantum Security Pipeline for Heterogeneous Data
# Using AES-256-GCM and ML-KEM-1024

Reproducibility package.

## Environment

    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt

## Tests

    python scripts\test_kdf.py
    python scripts\test_entropy_router.py

## Corpora

D1 is real-world content assembled by the authors and is not redistributed;
`results/manifests/D1_sha256.txt` lists the SHA-256 of every file.
D2 and D3 are generated deterministically from the seed in `config/corpus.json`.

    python scripts\build_corpus.py --corpus D2 --out <path> --seed 20260801
    python scripts\build_corpus.py --corpus D3 --out <path> --seed 20260801

## Measurement

    python scripts\run_ablation.py --configs A B C D E --corpus <path> --replicates 10
    python scripts\run_campaign.py --corpora D1 D2 D3 --replicates 10 --root <path>
    python scripts\fit_cost_model.py
