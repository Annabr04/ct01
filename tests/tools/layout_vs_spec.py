#!/usr/bin/env python3
"""Compare the C++ layout header (dump_layout) with the layout spec log (read-only).
The spec log lists the SIGNED record's trailer offsets (tag 216, sig 248, crc 312), as does kFieldTable."""
import subprocess, sys
ours = subprocess.run([sys.argv[1]], capture_output=True, text=True, check=True).stdout.splitlines()
spec = open(sys.argv[2]).read().splitlines()
want = [spec[0]] + [l for l in spec[1:] if len(l.split()) == 3 and l.split()[0].isdigit()]
if ours != want:
    for a, b in zip(ours + [""] * 50, want + [""] * 50):
        if a != b: print(f"ours {a!r} spec {b!r}")
    sys.exit(1)
print(f"layout header == spec log: {len(ours) - 1} fields, {ours[0]}")
