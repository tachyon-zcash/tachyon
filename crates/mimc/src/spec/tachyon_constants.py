#!/usr/bin/env python3
"""
Generate a MiMC round-constant blob for a Tachyon MiMC spec in the given personalization domain.

Writes `src/{domain}_{rounds}.bin` next to this script.

Standard library only.
"""

import argparse
import hashlib
from pathlib import Path

# Four little-endian u64 limbs per field element (the `Fp::from_raw` layout).
LIMB_BYTES = 32


def main():
    parser = argparse.ArgumentParser(description="Generate a MiMC round-constant blob.")
    parser.add_argument("modulus", choices=("pallas", "vesta"))
    parser.add_argument("domain")
    parser.add_argument("rounds", type=int)
    args = parser.parse_args()

    modulus = {
        "pallas": 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001,
        "vesta": 0x40000000000000000000000000000000224698FC0994A8DD8C46EB2100000001,
    }[args.modulus]

    person = args.domain.encode("utf-8")
    constants = [0]
    for index in range(1, args.rounds):
        digest = hashlib.blake2b(
            index.to_bytes(8, "little"), digest_size=64, person=person
        ).digest()
        constants.append(int.from_bytes(digest, "little") % modulus)

    blob = b"".join(c.to_bytes(LIMB_BYTES, "little") for c in constants)
    name = f"{args.domain}.bin"
    output = Path(__file__).resolve().parent / name
    output.write_bytes(blob)


if __name__ == "__main__":
    main()
