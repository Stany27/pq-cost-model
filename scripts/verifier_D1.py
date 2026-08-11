"""
Balance check for D1, in bytes rather than in file count.

The file-count balance is misleading: a corpus can hold 50% compressible files
and still send 99% of its bytes down the bypass path, which would make
configurations B and E indistinguishable in the ablation.

    python scripts/verifier_D1.py
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path

CSV = Path("results/entropy_D1.csv")
SEUIL = 7.5
CIBLE_MIN, CIBLE_MAX = 35.0, 65.0


def main():
    if not CSV.exists():
        sys.exit(f"{CSV} not found. Run entropy_profile.py first.")

    lignes = list(csv.DictReader(CSV.open()))
    if not lignes:
        sys.exit("Empty profile.")

    octets = defaultdict(int)
    nombre = defaultdict(int)
    par_ext = defaultdict(lambda: [0, 0, 0.0])

    for r in lignes:
        e = float(r["entropy_bits_per_byte"])
        n = int(r["size_bytes"])
        fam = "haute" if e > SEUIL else "basse"
        octets[fam] += n
        nombre[fam] += 1
        c = par_ext[r["extension"]]
        c[0] += 1
        c[1] += n
        c[2] += e

    total_o = sum(octets.values())
    total_n = sum(nombre.values())
    ph = 100 * octets["haute"] / total_o
    pb = 100 * octets["basse"] / total_o

    print(f"\n  {total_n} fichiers, {total_o / 2**30:.2f} Go\n")
    print(f"  {'famille':10} {'fichiers':>9} {'% fich.':>9} {'volume':>10} {'% volume':>10}")
    for fam in ("haute", "basse"):
        print(f"  {fam:10} {nombre[fam]:9} {100 * nombre[fam] / total_n:8.1f}% "
              f"{octets[fam] / 2**30:9.2f} Go {100 * octets[fam] / total_o:9.1f}%")

    print(f"\n  {'extension':12} {'nb':>5} {'Mo':>9} {'entropie moy.':>14} {'famille':>9}")
    for ext, (n, o, se) in sorted(par_ext.items(), key=lambda x: -x[1][1])[:14]:
        moy = se / n
        print(f"  {ext:12} {n:5} {o / 2**20:9.1f} {moy:14.3f} "
              f"{'haute' if moy > SEUIL else 'basse':>9}")

    print(f"\n  {'=' * 58}")
    if CIBLE_MIN <= ph <= CIBLE_MAX:
        print(f"  Équilibre atteint : {ph:.1f} % / {pb:.1f} %  (cible 35–65)")
        print("  Le corpus peut servir. Passez au manifeste.\n")
        return 0

    manque = "basse" if ph > CIBLE_MAX else "haute"
    part = octets[manque] / 2**20
    besoin = total_o / 2**20 * 0.45 - part
    print(f"  Déséquilibre : {ph:.1f} % haute / {pb:.1f} % basse  (cible 35–65)")
    print(f"  Il manque environ {besoin:.0f} Mo de contenu à {manque} entropie.\n")

    if manque == "basse":
        print("  Sources de texte volumineux, par ordre de rendement :")
        print("    - C:\\Windows\\Logs et C:\\Windows\\System32\\LogFiles")
        print("    - un dépôt de code cloné : git clone --depth 1 https://github.com/python/cpython")
        print("    - des exports CSV ou un mysqldump")
        print("    - les fichiers .py de .venv\\Lib\\site-packages")
    else:
        print("  Ajoutez des photographies, une vidéo ou une archive ZIP.")
    print()
    return 1


if __name__ == "__main__":
    sys.exit(main())
