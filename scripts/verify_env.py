"""
Environment check.

Compares the installed package versions against the manifest used for the
published measurements, and reports whether the optional native ML-KEM
implementation is available.

Exits non-zero if any pinned version differs, so that a measurement run cannot
silently proceed in an environment other than the published one.

    python scripts/verify_env.py
"""

import platform
import sys
from importlib.metadata import PackageNotFoundError, version

PINNED = {
    "cryptography": "44.0.0",
    "kyber-py": "1.0.1",
    "numpy": "2.2.1",
    "pandas": "2.2.3",
    "scipy": "1.15.1",
    "statsmodels": "0.14.4",      # het_breuschpagan, linear_reset
    "torch": "2.5.1",
    "scikit-image": "0.25.0",
    "matplotlib": "3.10.0",
    "zstandard": "0.23.0",
}

OPTIONAL = {
    "liboqs-python": "0.12.0",    # native ML-KEM; absence limits the study
}


def check(pins, mandatory):
    problems = []
    for pkg, want in sorted(pins.items()):
        try:
            got = version(pkg)
        except PackageNotFoundError:
            state = "MISSING"
            problems.append((pkg, want, state))
        else:
            state = "ok" if got == want else f"got {got}"
            if got != want:
                problems.append((pkg, want, state))
        print(f"  {pkg:18} expected {want:10} {state}")
    return problems


def main():
    print(f"Python   {platform.python_version()}  (expected 3.13.7)")
    print(f"Platform {platform.platform()}\n")

    print("Pinned packages")
    hard = check(PINNED, True)

    print("\nOptional packages")
    soft = check(OPTIONAL, False)

    print()
    if hard:
        print("FAIL: the environment does not match the published manifest.")
        print("      Rebuild with: docker build -t pqcost:1.0 -f env/Dockerfile .")
        sys.exit(1)

    if soft:
        print("WARNING: native ML-KEM is unavailable. Only the pure-Python")
        print("         implementation can be measured, which bounds t_KEM from")
        print("         above by roughly two orders of magnitude.")

    if platform.python_version() != "3.13.7":
        print("WARNING: Python version differs from the published manifest.")

    print("Environment matches the published manifest.")


if __name__ == "__main__":
    main()
