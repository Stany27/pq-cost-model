"""
SHA-256 manifest for a corpus that is not redistributed.

D1 holds real content that cannot be published. The manifest lets a reviewer
verify that a locally assembled corpus matches ours file by file, without the
files themselves ever leaving your machine.

    python scripts/make_manifest.py --corpus corpora/D1 \
           --out results/manifests/D1_sha256.txt
"""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

BLOC = 1 << 20


def sha256(chemin: Path) -> str:
    h = hashlib.sha256()
    with chemin.open("rb") as fh:
        for bloc in iter(lambda: fh.read(BLOC), b""):
            h.update(bloc)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    racine = Path(args.corpus)
    fichiers = sorted(p for p in racine.rglob("*") if p.is_file())
    if not fichiers:
        raise SystemExit(f"No files under {racine}")

    lignes, total = [], 0
    par_ext = Counter()
    octets_ext = Counter()

    for p in fichiers:
        taille = p.stat().st_size
        empreinte = sha256(p)
        rel = p.relative_to(racine).as_posix()
        lignes.append(f"{empreinte}  {taille:>12}  {rel}")
        total += taille
        ext = p.suffix.lower() or "(none)"
        par_ext[ext] += 1
        octets_ext[ext] += taille

    sortie = Path(args.out)
    sortie.parent.mkdir(parents=True, exist_ok=True)
    sortie.write_text("\n".join(lignes) + "\n")

    resume = {
        "corpus": racine.name,
        "files": len(fichiers),
        "bytes": total,
        "gb": round(total / 1024 ** 3, 3),
        "mean_file_mb": round(total / len(fichiers) / 1024 ** 2, 3),
        "by_extension": {
            ext: {"files": n, "gb": round(octets_ext[ext] / 1024 ** 3, 3)}
            for ext, n in par_ext.most_common()
        },
    }
    sortie.with_suffix(".summary.json").write_text(json.dumps(resume, indent=2))

    print(f"  {len(fichiers)} files, {resume['gb']} GB, "
          f"mean {resume['mean_file_mb']} MB\n")
    print(f"  {'extension':12} {'files':>6} {'GB':>8}")
    for ext, n in par_ext.most_common():
        print(f"  {ext:12} {n:6} {octets_ext[ext] / 1024**3:8.3f}")

    print(f"\n  -> {sortie}")
    print(f"  -> {sortie.with_suffix('.summary.json')}")


if __name__ == "__main__":
    main()
