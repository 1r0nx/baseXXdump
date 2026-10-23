"""Tests for baseXXdump.

Three layers:
  1. unit    — helpers and a representative decoder per family
  2. scan    — round-trip: plant a known encoded blob in noise, assert scan()
               finds it with the right encoder, decoded value and offset
  3. cli     — run the real CLI as a subprocess (filter, stdin, -l, errors) and
               a regression check against the committed hard fixture test/file.bin

Pure stdlib; run with `pytest` from the repo root.
"""
import base64
import json
import os
import string
import subprocess
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
import baseXXdump as D

SCRIPT = os.path.join(HERE, "..", "baseXXdump.py")
FIXTURE = os.path.join(HERE, "file.bin")
BARRIER = "\x00\x00\x00\x00"  # isolates a blob from surrounding noise


# ─── reference encoders (independent of the tool) ──────────────────────────────

def b58enc(data, alphabet):
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return alphabet[0] * pad + out


def b92enc(data):
    C = D.BASE92_CHARS
    bits = "".join(f"{byte:08b}" for byte in data)
    out, i = "", 0
    while i + 13 <= len(bits):
        val = int(bits[i:i + 13], 2)
        out += C[val // 91] + C[val % 91]
        i += 13
    rem = bits[i:]
    if rem:
        if len(rem) <= 6:
            out += C[int(rem.ljust(6, "0"), 2)]
        else:
            val = int(rem.ljust(13, "0"), 2)
            out += C[val // 91] + C[val % 91]
    return out


# ─── 1. unit tests ─────────────────────────────────────────────────────────────

def test_try_decode_bytes_utf8_then_latin1():
    assert D.try_decode_bytes(b"hello") == "hello"
    # invalid UTF-8 falls back to latin-1 (never raises, never returns None)
    assert D.try_decode_bytes(b"\xff\xfe") == "\xff\xfe"


def test_is_printable_threshold():
    assert D.is_printable("CTF{ok}")
    assert not D.is_printable("\x00\x01\x02\x03\x04")
    assert not D.is_printable("")


@pytest.mark.parametrize("decoder,encoded,expected", [
    (D.decode_hex_plain, b"Hello".hex(), "Hello"),
    (D.decode_base64_standard, base64.b64encode(b"Hello").decode(), "Hello"),
    (D.decode_base32_standard, base64.b32encode(b"Hello").decode(), "Hello"),
    (D.decode_base58_bitcoin, b58enc(b"Hello", D.BASE58_BITCOIN), "Hello"),
    (D.decode_base92, b92enc(b"Hello"), "Hello"),
])
def test_decoder_known_vectors(decoder, encoded, expected):
    assert decoder(encoded) == expected


# ─── 2. scan round-trip: blob planted in noise is found at the right offset ─────

def _dec_sep(data):  # ascii-decimal with ';' separator
    return ";".join(str(b) for b in data)


def _bx(data):       # \x hex
    return "".join(f"\\x{b:02x}" for b in data)


def _bin(data):      # raw 0/1
    return "".join(f"{b:08b}" for b in data)


FLAG = b"CTF{scan_roundtrip}"
SCAN_CASES = [
    ("hex", FLAG.hex(),                                   FLAG.decode()),
    ("bx",  _bx(FLAG),                                    FLAG.decode()),
    ("dec", _dec_sep(FLAG),                               FLAG.decode()),
    ("b64", base64.b64encode(FLAG).decode(),              FLAG.decode()),
    ("b32", base64.b32encode(FLAG).decode(),              FLAG.decode()),
    ("b58btc", b58enc(FLAG, D.BASE58_BITCOIN),            FLAG.decode()),
    ("b92", b92enc(FLAG),                                 FLAG.decode()),
]


@pytest.mark.parametrize("name,encoded,expected", SCAN_CASES, ids=[c[0] for c in SCAN_CASES])
def test_scan_finds_planted_blob(name, encoded, expected):
    encoders = D.build_encoders(minlen=8)
    prefix = "garbage noise \x00\x00 "
    text = prefix + BARRIER + encoded + BARRIER + " more noise"
    results = D.scan(text, name, encoders[name], min_decoded_len=3)
    hits = [r for r in results if r["decoded"] == expected]
    assert hits, f"{name}: {expected!r} not found in {[r['decoded'] for r in results]}"
    # offset points at the encoded blob (right after the barrier)
    assert text[hits[0]["offset"]:].startswith(encoded[:4])


def test_scan_binary_special():
    encoders = D.build_encoders(minlen=8)
    flag = b"CTF{bin}"
    text = "xx" + BARRIER + _bin(flag) + BARRIER + "yy"
    results = D.scan(text, "bin", encoders["bin"], min_decoded_len=len(flag))
    assert any(r["decoded"] == flag.decode() for r in results)


# ─── 3. CLI / integration ──────────────────────────────────────────────────────

def run_cli(*args, stdin=None):
    return subprocess.run(
        [sys.executable, SCRIPT, *args],
        capture_output=True, input=stdin,
    )


# the 24 flags planted in the committed hard fixture test/file.bin
FIXTURE_FLAGS = {
    "CTF{ampersand_h_dump}", "CTF{ascii85_delimited}", "CTF{ascii85_plain_dump}",
    "CTF{ascii_decimal_dump}", "CTF{backslash_x_dump}", "CTF{base36_dump_data}",
    "CTF{base45_dump_data}", "CTF{base58_bitcoin}", "CTF{base58_flickr_dump}",
    "CTF{base58_ripple_dump}", "CTF{base62_dump_data}",
    "CTF{base64_mime_wrapped_over_multiple_lines_for_testing}",
    "CTF{base64_std_dump}", "CTF{base64_urlsafe_dump}", "CTF{base91_dump_data}",
    "CTF{base92_dump_data}", "CTF{big_endian_hex}", "CTF{comma_hex_dump}",
    "CTF{hex_plain_dump}", "CTF{little_endian_hex}", "CTF{percent_hex_dump}",
    "CTF{raw_binary_dump}", "CTF{unicode_bu_dump}", "CTF{unicode_pu_dump}",
}


def test_fixture_all_flags_recovered(tmp_path):
    """Regression + robustness: every planted flag is recovered from the hard fixture."""
    out_json = tmp_path / "res.json"
    p = run_cli(FIXTURE, "--filter", r"CTF\{", "--jsonoutput", str(out_json))
    assert p.returncode == 0
    results = json.load(open(out_json))
    found = {r["decoded"] for r in results}
    assert FIXTURE_FLAGS <= found, f"missing: {sorted(FIXTURE_FLAGS - found)}"


def test_fixture_does_not_crash():
    """The pathological fixture must be processed without error, quickly."""
    p = run_cli(FIXTURE)
    assert p.returncode == 0
    assert b"Traceback" not in p.stderr


def test_filter_reduces_noise():
    total = run_cli(FIXTURE).stdout.count(b"\xe2\x9c\x93")          # ✓
    filtered = run_cli(FIXTURE, "--filter", r"CTF\{").stdout.count(b"\xe2\x9c\x93")
    assert 0 < filtered < total


def test_stdin_equivalent_to_file():
    with open(FIXTURE, "rb") as f:
        data = f.read()
    piped = run_cli("--filter", r"CTF\{", stdin=data)
    assert piped.returncode == 0
    assert b"<stdin>" in piped.stdout
    assert b"CTF{base92_dump_data}" in piped.stdout


def test_list_encoders():
    p = run_cli("-l")
    assert p.returncode == 0
    for name in (b"b64", b"b92", b"hex", b"bin", b"dec"):
        assert name in p.stdout


def test_invalid_filter_regex_errors():
    p = run_cli(FIXTURE, "--filter", "[")
    assert p.returncode == 1
    assert b"invalid --filter regex" in p.stdout


def test_selecting_a_family():
    p = run_cli(FIXTURE, "-e", "base", "--filter", r"CTF\{")
    assert p.returncode == 0
    # base family recovers base-specific flags but not the hex/unicode ones
    assert b"CTF{base92_dump_data}" in p.stdout
