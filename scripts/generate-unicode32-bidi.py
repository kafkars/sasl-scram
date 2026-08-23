#!/usr/bin/env python3
"""Generate the RFC 3454 Unicode 3.2 bidirectional-property tables."""

from __future__ import annotations

import argparse
import stringprep
import sys
import unicodedata
from collections.abc import Callable, Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "src/saslprep/unicode32_bidi.rs"
MAX_CODE_POINT = 0x110000
VALUES_PER_LINE = 16


def scalar_values() -> Iterable[int]:
    for value in range(MAX_CODE_POINT):
        if not 0xD800 <= value <= 0xDFFF:
            yield value


def contiguous_ranges(predicate: Callable[[str], bool]) -> list[tuple[int, int]]:
    output: list[tuple[int, int]] = []
    start: int | None = None
    previous: int | None = None
    for value in scalar_values():
        if not predicate(chr(value)):
            continue
        if start is None:
            start = value
        elif previous is not None and value != previous + 1:
            output.append((start, previous))
            start = value
        previous = value
    if start is not None and previous is not None:
        output.append((start, previous))
    return output


def array(name: str, ranges: list[tuple[int, int]]) -> str:
    values = []
    for bounds in ranges:
        for value in bounds:
            values.extend(value.to_bytes(3, byteorder="big"))
    lines = []
    for offset in range(0, len(values), VALUES_PER_LINE):
        line = ", ".join(f"0x{value:02X}" for value in values[offset : offset + VALUES_PER_LINE])
        lines.append(f"    {line},")
    return f"pub(super) const {name}: &[u8] = &[\n" + "\n".join(lines) + "\n];\n"


def render() -> str:
    if unicodedata.ucd_3_2_0.unidata_version != "3.2.0":
        raise RuntimeError("Python does not expose the required Unicode 3.2 database")
    d1 = contiguous_ranges(stringprep.in_table_d1)
    d2 = contiguous_ranges(stringprep.in_table_d2)
    header = """//! Generated RFC 3454 D.1 and D.2 tables for Unicode 3.2.0.
//!
//! Regenerate with `python3 scripts/generate-unicode32-bidi.py --write`.

"""
    functions = """
pub(super) fn contains(ranges: &[u8], character: char) -> bool {
    let value = character as u32;
    let mut lower = 0;
    let mut upper = ranges.len() / 6;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        let offset = middle * 6;
        let start = decode(ranges, offset);
        let end = decode(ranges, offset + 3);
        if value < start {
            upper = middle;
        } else if value > end {
            lower = middle + 1;
        } else {
            return true;
        }
    }
    false
}

fn decode(ranges: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([0, ranges[offset], ranges[offset + 1], ranges[offset + 2]])
}
"""
    return header + array("BIDI_R_OR_AL", d1) + "\n" + array("BIDI_L", d2) + functions


def check(expected: str) -> int:
    try:
        actual = OUTPUT.read_text(encoding="utf-8")
    except FileNotFoundError:
        actual = ""
    if actual != expected:
        print(f"generated Unicode 3.2 table is stale: {OUTPUT.relative_to(ROOT)}", file=sys.stderr)
        return 1
    print("Unicode 3.2 bidirectional tables verified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--stdout", action="store_true")
    mode.add_argument("--write", action="store_true")
    arguments = parser.parse_args()
    expected = render()
    if arguments.stdout:
        sys.stdout.write(expected)
        return 0
    if arguments.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(expected, encoding="utf-8")
        return 0
    return check(expected)


if __name__ == "__main__":
    sys.exit(main())
