"""
Deterministic corpus builder for D2 and D3.

Neither corpus is ever stored or transferred: both are regenerated from a seed.
A given seed always produces byte-identical files, so a reviewer can rebuild
them and check the SHA-256 manifest without downloading 55 GB.

    python scripts/build_corpus.py --corpus D2 --out /mnt/ramdisk/D2 --seed 20260801
    python scripts/build_corpus.py --corpus D3 --out /mnt/ramdisk/D3 --seed 20260801

High-entropy content comes from AES in counter mode rather than from Python's
own generator: it runs at roughly 400 MB/s against 55, which turns the 40 GB of
D3 from twelve minutes into under two, and it stays exactly reproducible from
key and nonce.

Write the seed down. It is the only thing that makes the corpora reproducible.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import string
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOC = 4 << 20          # 4 MiB streaming chunk; caps peak memory per file

# --------------------------------------------------------------------------
# Corpus profiles.
#
# The type mix matters more than it looks. An entropy-aware router can only be
# evaluated on a corpus containing both compressible and incompressible
# content; a corpus of JPEG and MP4 alone would make configurations B and E
# indistinguishable, and the paper's central claim untestable.
# --------------------------------------------------------------------------
PROFILES = {
    "D2": {
        "label": "many small files, key-encapsulation bound",
        "target_gb": 15.0,
        "files": 23_785,
        "mix": [
            # extension, share of files, size range in KB, entropy family
            (".log",   0.34, (8, 900),      "low"),
            (".csv",   0.18, (16, 1_200),   "low"),
            (".json",  0.12, (4, 400),      "low"),
            (".pcap",  0.20, (64, 3_000),   "high"),
            (".bin",   0.16, (128, 4_000),  "high"),
        ],
    },
    "D3": {
        "label": "few large files, throughput bound",
        "target_gb": 40.0,
        "files": 835,
        "mix": [
            (".bin",   0.62, (20_000, 90_000),  "high"),
            (".mp4",   0.20, (30_000, 120_000), "high"),
            (".sql",   0.12, (10_000, 60_000),  "low"),
            (".csv",   0.06, (8_000, 40_000),   "low"),
        ],
    },
}

MOTS = ("request served timeout retry accepted rejected flush commit rollback "
        "session token expired granted denied audit record index scan merge "
        "latency throughput checksum verified quarantine dispatch").split()


def flux_haute_entropie(cle: bytes, nonce: bytes):
    """
    Deterministic high-entropy stream, near 8 bits per byte.

    AES-CTR over a zero plaintext: reproducible from (key, nonce), and roughly
    seven times faster than random.randbytes on a modern core.
    """
    chiffreur = Cipher(algorithms.AES(cle), modes.CTR(nonce)).encryptor()

    def suivant(n: int) -> bytes:
        return chiffreur.update(bytes(n))

    return suivant


def bloc_basse_entropie(rng: random.Random, ext: str, lignes: int = 4000) -> bytes:
    """
    One block of structured text: logs, CSV, JSON or SQL dumps.

    Entropy lands around 4 to 5 bits per byte, so the router should send this
    through the compressor. A fresh block is drawn for every chunk written, so
    a large file does not degenerate into a repeated pattern that a
    wide-window compressor would collapse unrealistically.
    """
    out = []
    for i in range(lignes):
        if ext == ".csv":
            out.append(f"{1_700_000_000 + i},{rng.randrange(1000)},"
                       f"{rng.choice(MOTS)},{rng.random():.6f},"
                       f"{rng.choice(('OK', 'WARN', 'ERROR'))}\n")
        elif ext == ".json":
            out.append(f'{{"ts":{1_700_000_000 + i},'
                       f'"lvl":"{rng.choice(("INFO", "WARN"))}",'
                       f'"msg":"{rng.choice(MOTS)} {rng.choice(MOTS)}",'
                       f'"id":{rng.randrange(10**6)}}}\n')
        elif ext == ".sql":
            out.append(f"INSERT INTO events (id, ts, kind, payload) VALUES "
                       f"({i}, {1_700_000_000 + i}, '{rng.choice(MOTS)}', "
                       f"'{''.join(rng.choices(string.ascii_lowercase, k=24))}');\n")
        else:
            out.append(f"2026-08-{rng.randrange(1, 29):02d}"
                       f"T{rng.randrange(24):02d}:{rng.randrange(60):02d}:"
                       f"{rng.randrange(60):02d}Z "
                       f"{rng.choice(('INFO', 'WARN', 'ERROR', 'DEBUG'))} "
                       f"{rng.choice(MOTS)} {rng.choice(MOTS)} "
                       f"id={rng.randrange(10**6)}\n")
    return "".join(out).encode()


def ecrire_fichier(chemin: Path, taille: int, famille: str, ext: str,
                   rng: random.Random, suivant) -> str:
    """Stream one file to disk and return its SHA-256, without holding it in RAM."""
    h = hashlib.sha256()
    reste = taille
    with chemin.open("wb") as fh:
        while reste > 0:
            n = min(reste, BLOC)
            if famille == "high":
                data = suivant(n)
            else:
                bloc = bloc_basse_entropie(rng, ext)
                while len(bloc) < n:
                    bloc += bloc_basse_entropie(rng, ext)
                data = bloc[:n]
            fh.write(data)
            h.update(data)
            reste -= n
    return h.hexdigest()


def construire(nom: str, sortie: Path, graine: int) -> dict:
    profil = PROFILES[nom]

    # hash() on a string is salted per process in Python 3 and cannot be used
    # to derive a sub-seed: two runs with the same --seed would silently
    # produce different corpora. A stable digest is required.
    sous_graine = int.from_bytes(hashlib.sha256(nom.encode()).digest()[:4], "big")
    rng = random.Random(graine ^ sous_graine)

    materiel = hashlib.sha256(f"{graine}:{nom}:stream".encode()).digest()
    suivant = flux_haute_entropie(materiel[:32], materiel[:16])

    sortie.mkdir(parents=True, exist_ok=True)
    cible = int(profil["target_gb"] * 1024 ** 3)
    total_fichiers = profil["files"]

    plan = [(ext, max(1, round(total_fichiers * part)), kmin, kmax, fam)
            for ext, part, (kmin, kmax), fam in profil["mix"]]

    brut = sum(n * (kmin + kmax) / 2 * 1024 for _, n, kmin, kmax, _ in plan)
    echelle = cible / brut if brut else 1.0

    manifeste, ecrit, index = [], 0, 0
    depart = time.perf_counter()

    for ext, n, kmin, kmax, famille in plan:
        for _ in range(n):
            taille = max(512, int(rng.uniform(kmin, kmax) * 1024 * echelle))
            chemin = sortie / f"{nom.lower()}_{index:06d}{ext}"
            empreinte = ecrire_fichier(chemin, taille, famille, ext, rng, suivant)

            manifeste.append({"file": chemin.name, "bytes": taille,
                              "sha256": empreinte, "family": famille})
            ecrit += taille
            index += 1

            if index % 2000 == 0 or (famille == "high" and index % 100 == 0):
                ecoule = time.perf_counter() - depart
                debit = ecrit / 1024 ** 2 / ecoule if ecoule else 0
                reste = (cible - ecrit) / 1024 ** 2 / debit if debit else 0
                print(f"    {index:6}/{total_fichiers}  {ecrit / 1024**3:6.2f} GB  "
                      f"{debit:6.0f} MB/s  {reste / 60:4.1f} min left", flush=True)

    return {
        "corpus": nom,
        "label": profil["label"],
        "seed": graine,
        "files": index,
        "bytes": ecrit,
        "gb": round(ecrit / 1024 ** 3, 3),
        "mean_file_mb": round(ecrit / index / 1024 ** 2, 3),
        "build_seconds": round(time.perf_counter() - depart, 1),
        "manifest": manifeste,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, choices=sorted(PROFILES))
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--scale", type=float, default=1.0,
                    help="fraction of full size, for a quick dry run")
    ap.add_argument("--force", action="store_true",
                    help="rebuild without asking if the target is not empty")
    args = ap.parse_args()

    profil = PROFILES[args.corpus]
    if args.scale != 1.0:
        profil["target_gb"] *= args.scale
        profil["files"] = max(10, int(profil["files"] * args.scale))
        print(f"  dry run at {args.scale:g} of full size")

    sortie = Path(args.out)

    # Refuse to overwrite silently: a half-built corpus is worse than none.
    if sortie.exists() and any(sortie.iterdir()):
        print(f"  {sortie} already contains files.")
        if not args.force and input("  Delete and rebuild? (yes/no) ").strip().lower() != "yes":
            sys.exit(0)
        for p in sortie.iterdir():
            p.unlink()

    try:
        libre = shutil.disk_usage(sortie.parent).free / 1024 ** 3
        besoin = profil["target_gb"] * 1.05
        print(f"  space: {libre:.1f} GB free, {besoin:.1f} GB needed")
        if libre < besoin:
            sys.exit(f"  Not enough space under {sortie.parent}.")
    except OSError:
        pass

    print(f"  Building {args.corpus} -> {sortie}  (seed {args.seed})")
    resume = construire(args.corpus, sortie, args.seed)

    manifeste = sortie.parent / f"{args.corpus}_manifest.json"
    manifeste.write_text(json.dumps(resume, indent=2))

    print(f"\n  {resume['files']} files, {resume['gb']} GB, "
          f"mean {resume['mean_file_mb']} MB, built in "
          f"{resume['build_seconds'] / 60:.1f} min")
    print(f"  -> {manifeste}")


if __name__ == "__main__":
    main()
