#!/usr/bin/env python3
"""
baseXXdump.py
─────────────
Multi-format encoded-data extractor/decoder for CTF file analysis.

Scans a file for candidate encoded blobs (hex variants, baseXX strings,
separated ascii-decimal, raw binary 0/1, and unicode-escaped bytes) and
tries to decode every candidate into readable text.

Self-contained: all base-N decoders (originally from baseXX.py) are
inlined below, so this script has no external file dependency.

Inspired by baseXX.py (own tool) and base64dump.py (Didier Stevens).
"""

import argparse
import base64
import json
import os
import re
import string
import sys

TRUNC = 60


# ─────────────────────────────────────────────
# CORE UTILITIES (from baseXX.py)
# ─────────────────────────────────────────────

def try_decode_bytes(raw: bytes) -> str:
    """Attempt to decode raw bytes into a readable string."""
    for enc in ("utf-8", "latin-1", "ascii"):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.hex()


def is_printable(s: str) -> bool:
    """Return True if at least 70% of the string's characters are printable."""
    if not s:
        return False
    printable = sum(1 for c in s if c in string.printable)
    return printable / len(s) >= 0.7


# ─────────────────────────────────────────────
# BASE32 (from baseXX.py)
# ─────────────────────────────────────────────

def decode_base32_standard(s: str):
    """Base32 standard RFC 4648 (A-Z, 2-7)."""
    try:
        pad = (8 - len(s) % 8) % 8
        result = base64.b32decode(s.upper() + "=" * pad)
        return try_decode_bytes(result)
    except Exception:
        return None


def decode_base32_hex(s: str):
    """Base32 Hex (0-9, A-V) — RFC 4648 §7."""
    STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    try:
        upper = s.upper()
        translated = upper.translate(str.maketrans(HEX, STANDARD))
        pad = (8 - len(translated) % 8) % 8
        result = base64.b32decode(translated + "=" * pad)
        return try_decode_bytes(result)
    except Exception:
        return None


def decode_base32_crockford(s: str):
    """Base32 Crockford — human-friendly alphabet (no I, L, O, U)."""
    CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    try:
        upper = s.upper().replace("I", "1").replace("L", "1").replace("O", "0")
        translated = ""
        for c in upper:
            idx = CROCKFORD.find(c)
            if idx == -1:
                return None
            translated += STANDARD[idx]
        pad = (8 - len(translated) % 8) % 8
        result = base64.b32decode(translated + "=" * pad)
        return try_decode_bytes(result)
    except Exception:
        return None


# ─────────────────────────────────────────────
# BASE45 (from baseXX.py)
# ─────────────────────────────────────────────

BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def decode_base45(s: str):
    """Base45 — RFC 9285 (used in COVID QR codes)."""
    try:
        n = len(s)
        if n % 3 == 1:
            return None

        res = []
        for i in range(0, n, 3):
            chunk = s[i:i + 3]
            if len(chunk) == 2:
                c, d = [BASE45_ALPHABET.index(x) for x in chunk]
                val = c + d * 45
                if val > 0xFF:
                    return None
                res.append(val)
            else:
                c, d, e = [BASE45_ALPHABET.index(x) for x in chunk]
                val = c + d * 45 + e * 45 * 45
                if val > 0xFFFF:
                    return None
                res.append(val >> 8)
                res.append(val & 0xFF)

        return try_decode_bytes(bytes(res))
    except Exception:
        return None


# ─────────────────────────────────────────────
# BASE58 (from baseXX.py)
# ─────────────────────────────────────────────

BASE58_BITCOIN = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_FLICKR = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
BASE58_RIPPLE = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def _base58_decode(s: str, alphabet: str):
    """Generic Base58 decoder."""
    try:
        n = 0
        for char in s:
            idx = alphabet.find(char)
            if idx == -1:
                return None
            n = n * 58 + idx
        result = []
        while n > 0:
            result.append(n & 0xFF)
            n >>= 8
        pad = len(s) - len(s.lstrip(alphabet[0]))
        result.extend([0] * pad)
        result.reverse()
        return try_decode_bytes(bytes(result))
    except Exception:
        return None


def decode_base58_bitcoin(s):
    return _base58_decode(s, BASE58_BITCOIN)


def decode_base58_flickr(s):
    return _base58_decode(s, BASE58_FLICKR)


def decode_base58_ripple(s):
    return _base58_decode(s, BASE58_RIPPLE)


# ─────────────────────────────────────────────
# BASE62 (from baseXX.py)
# ─────────────────────────────────────────────

BASE62_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase


def decode_base62(s: str):
    """Base62 standard (0-9, A-Z, a-z)."""
    try:
        n = 0
        for char in s:
            idx = BASE62_ALPHABET.find(char)
            if idx == -1:
                return None
            n = n * 62 + idx
        result = []
        while n > 0:
            result.append(n & 0xFF)
            n >>= 8
        result.reverse()
        if not result:
            return None
        return try_decode_bytes(bytes(result))
    except Exception:
        return None


# ─────────────────────────────────────────────
# BASE64 (from baseXX.py)
# ─────────────────────────────────────────────

def decode_base64_standard(s: str):
    """Base64 standard (RFC 4648) with automatic padding."""
    try:
        pad = (4 - len(s) % 4) % 4
        result = base64.b64decode(s + "=" * pad)
        return try_decode_bytes(result)
    except Exception:
        return None


def decode_base64_urlsafe(s: str):
    """Base64 URL-safe (- and _ instead of + and /)."""
    try:
        pad = (4 - len(s) % 4) % 4
        result = base64.urlsafe_b64decode(s + "=" * pad)
        return try_decode_bytes(result)
    except Exception:
        return None


def decode_base64_mime(s: str):
    """Base64 MIME — ignores line breaks."""
    try:
        cleaned = s.replace("\n", "").replace("\r", "").replace(" ", "")
        return decode_base64_standard(cleaned)
    except Exception:
        return None


# ─────────────────────────────────────────────
# BASE85 (from baseXX.py)
# ─────────────────────────────────────────────

def decode_base85_ascii85(s: str):
    """Base85 Ascii85 (Adobe / PostScript)."""
    try:
        data = s.strip()
        if not data.startswith("<~"):
            data = "<~" + data
        if not data.endswith("~>"):
            data = data + "~>"
        result = base64.a85decode(data, adobe=True)
        return try_decode_bytes(result)
    except Exception:
        return None


def decode_base85_rfc1924(s: str):
    """Base85 RFC 1924 (Python btoa / ZeroMQ)."""
    try:
        result = base64.b85decode(s)
        return try_decode_bytes(result)
    except Exception:
        return None


def decode_base85_plain(s: str):
    """Base85 without Adobe delimiters."""
    try:
        result = base64.a85decode(s, adobe=False)
        return try_decode_bytes(result)
    except Exception:
        return None


# ─────────────────────────────────────────────
# BASE91 (from baseXX.py)
# ─────────────────────────────────────────────

BASE91_ALPHABET = (
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    '0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
)


def decode_base91(s: str):
    """Base91 — compact binary-to-text encoding."""
    try:
        decode_table = {c: i for i, c in enumerate(BASE91_ALPHABET)}
        v = -1
        b = 0
        n = 0
        result = bytearray()

        for c in s:
            if c not in decode_table:
                return None
            p = decode_table[c]
            if v < 0:
                v = p
            else:
                v += p * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                v = -1
                while n > 7:
                    result.append(b & 255)
                    b >>= 8
                    n -= 8

        if v > -1:
            result.append((b | v << n) & 255)

        return try_decode_bytes(bytes(result))
    except Exception:
        return None


# ─────────────────────────────────────────────
# BASE92 (from baseXX.py)
# ─────────────────────────────────────────────

BASE92_CHARS = [chr(i) for i in range(34, 127) if i != 96]


def decode_base92(s: str):
    """Base92 — pair-based encoding (divisor 91, 13 bits/pair, 6 bits for trailing single char)."""
    try:
        if not s:
            return None
        try:
            vals = [BASE92_CHARS.index(c) for c in s]
        except ValueError:
            return None

        bits_str = ""
        i = 0
        while i < len(s) - 1:
            val = vals[i] * 91 + vals[i + 1]
            bits_str += f"{val:013b}"
            i += 2
        if len(s) % 2 == 1:
            bits_str += f"{vals[-1]:06b}"

        result = bytearray(
            int(bits_str[j:j + 8], 2)
            for j in range(0, len(bits_str) - 7, 8)
        )
        return try_decode_bytes(bytes(result)) if result else None
    except Exception:
        return None

COLORS = {
    "green": "\033[92m",
    "cyan": "\033[96m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "magenta": "\033[95m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def cprint(color, text):
    print(f"{COLORS.get(color, '')}{text}{COLORS['reset']}")


# ─────────────────────────────────────────────
# HEX FAMILY DECODERS
# ─────────────────────────────────────────────

def decode_hex_plain(s):
    """Plain hexadecimal, e.g. 6D6573736167652C..."""
    s2 = re.sub(r"\s+", "", s)
    if len(s2) % 2:
        s2 = s2[:-1]
    try:
        return try_decode_bytes(bytes.fromhex(s2))
    except Exception:
        return None


def decode_bx(s):
    r"""Backslash hexadecimal (\x), e.g. \x90\x90..."""
    tokens = re.findall(r"\\x([0-9A-Fa-f]{2})", s)
    if len(tokens) < 2:
        return None
    try:
        return try_decode_bytes(bytes(int(t, 16) for t in tokens))
    except Exception:
        return None


def decode_ah(s):
    """Ampersand hexadecimal (&H), e.g. &H90&H90..."""
    tokens = re.findall(r"&[Hh]([0-9A-Fa-f]{1,2})", s)
    if len(tokens) < 2:
        return None
    try:
        return try_decode_bytes(bytes(int(t, 16) for t in tokens))
    except Exception:
        return None


def decode_zxc(s):
    """Comma-separated 0x hex, 2 digits, e.g. 0x90,0x90,0x90..."""
    tokens = re.findall(r"0[xX]([0-9A-Fa-f]{1,2})", s)
    if len(tokens) < 2:
        return None
    try:
        return try_decode_bytes(bytes(int(t, 16) for t in tokens))
    except Exception:
        return None


def decode_zxbe(s):
    """0x hexadecimal, big-endian, e.g. 0x909090900x77eb..."""
    tokens = re.findall(r"0[xX]([0-9A-Fa-f]{1,8})", s)
    if len(tokens) < 2:
        return None
    try:
        raw = b""
        for t in tokens:
            if len(t) % 2:
                t = "0" + t
            raw += bytes.fromhex(t)
        return try_decode_bytes(raw)
    except Exception:
        return None


def decode_zxle(s):
    """0x hexadecimal, little-endian, e.g. 0x909090900xeb77..."""
    tokens = re.findall(r"0[xX]([0-9A-Fa-f]{1,8})", s)
    if len(tokens) < 2:
        return None
    try:
        raw = b""
        for t in tokens:
            if len(t) % 2:
                t = "0" + t
            raw += bytes.fromhex(t)[::-1]
        return try_decode_bytes(raw)
    except Exception:
        return None


def decode_pct(s):
    """Percent-encoded hex (URL-style), e.g. %90%90%eb%77..."""
    tokens = re.findall(r"%([0-9A-Fa-f]{2})", s)
    if len(tokens) < 2:
        return None
    try:
        return try_decode_bytes(bytes(int(t, 16) for t in tokens))
    except Exception:
        return None


# ─────────────────────────────────────────────
# UNICODE FAMILY DECODERS
# ─────────────────────────────────────────────

def decode_bu(s):
    r"""Backslash-u unicode, e.g. \u9090\ueb77..."""
    tokens = re.findall(r"\\u([0-9A-Fa-f]{4})", s)
    if len(tokens) < 2:
        return None
    try:
        return try_decode_bytes(bytes.fromhex("".join(tokens)))
    except Exception:
        return None


def decode_pu(s):
    """Percent-u unicode, e.g. %u9090%ueb77..."""
    tokens = re.findall(r"%u([0-9A-Fa-f]{4})", s)
    if len(tokens) < 2:
        return None
    try:
        return try_decode_bytes(bytes.fromhex("".join(tokens)))
    except Exception:
        return None


# ─────────────────────────────────────────────
# ASCII-DECIMAL FAMILY DECODER
# ─────────────────────────────────────────────

def decode_ascii_dec(s):
    """Decimal byte values with an arbitrary separator, e.g. 80;75;3;4 / 80-75-3-4"""
    nums = re.findall(r"\d{1,3}", s)
    if len(nums) < 4:
        return None
    try:
        vals = [int(n) for n in nums]
        if any(v > 255 for v in vals):
            return None
        return try_decode_bytes(bytes(vals))
    except Exception:
        return None


# ─────────────────────────────────────────────
# BASE36 (bonus, common in CTFs)
# ─────────────────────────────────────────────

BASE36_ALPHABET = string.digits + string.ascii_uppercase


def decode_base36(s):
    """Base36 standard (0-9, A-Z)."""
    try:
        n = 0
        for c in s.upper():
            idx = BASE36_ALPHABET.find(c)
            if idx == -1:
                return None
            n = n * 36 + idx
        result = []
        while n > 0:
            result.append(n & 0xFF)
            n >>= 8
        result.reverse()
        if not result:
            return None
        return try_decode_bytes(bytes(result))
    except Exception:
        return None


# ─────────────────────────────────────────────
# BINARY (0/1) — SPECIAL HANDLING
# Chunk on 7 and 8 bits, and test bit-offsets (skip 0..7 leading bits)
# ─────────────────────────────────────────────

def decode_binary_candidates(s, min_decoded_len):
    out = []
    for width in (8, 7):
        for skip in range(0, 8):
            bits = s[skip:]
            usable = len(bits) - (len(bits) % width)
            if usable < width:
                continue
            chunks = [bits[i:i + width] for i in range(0, usable, width)]
            try:
                raw = bytes(int(c, 2) for c in chunks)
            except Exception:
                continue
            decoded = try_decode_bytes(raw)
            if decoded and is_printable(decoded) and len(decoded) >= min_decoded_len:
                out.append((f"bin(w{width}-skip{skip})", decoded))
    return out


# ─────────────────────────────────────────────
# ENCODER REGISTRY
# family -> hex | unicode | ascii | binary | base
# ─────────────────────────────────────────────

def _class_regex(alphabet, minlen):
    return re.compile("[" + re.escape(alphabet) + "]{%d,}" % minlen)


def build_encoders(minlen):
    encoders = {}

    # ---- hex family ----
    encoders["hex"] = {
        "family": "hex", "desc": "hexadecimal, e.g. 6D6573736167652C...",
        "regex": re.compile(r"(?:[0-9A-Fa-f]{2}){%d,}" % max(2, minlen // 2)),
        "decode": decode_hex_plain,
    }
    encoders["bx"] = {
        "family": "hex", "desc": r"\x hexadecimal, e.g. \x90\x90...",
        "regex": re.compile(r"(?:\\x[0-9A-Fa-f]{2}){2,}"),
        "decode": decode_bx,
    }
    encoders["ah"] = {
        "family": "hex", "desc": "&H hexadecimal, e.g. &H90&H90...",
        "regex": re.compile(r"(?:&[Hh][0-9A-Fa-f]{1,2}){2,}"),
        "decode": decode_ah,
    }
    encoders["zxc"] = {
        "family": "hex", "desc": "0x hex, comma separated, e.g. 0x90,0x90,0x90...",
        "regex": re.compile(r"0[xX][0-9A-Fa-f]{1,2}(?:,0[xX][0-9A-Fa-f]{1,2}){1,}"),
        "decode": decode_zxc,
    }
    encoders["zxbe"] = {
        "family": "hex", "desc": "0x hex, big-endian, e.g. 0x909090900x77eb...",
        "regex": re.compile(r"(?:0[xX][0-9A-Fa-f]{1,8}){2,}"),
        "decode": decode_zxbe,
    }
    encoders["zxle"] = {
        "family": "hex", "desc": "0x hex, little-endian, e.g. 0x909090900xeb77...",
        "regex": re.compile(r"(?:0[xX][0-9A-Fa-f]{1,8}){2,}"),
        "decode": decode_zxle,
    }
    encoders["pct"] = {
        "family": "hex", "desc": "percent hex, e.g. %90%90%eb%77...",
        "regex": re.compile(r"(?:%[0-9A-Fa-f]{2}){2,}"),
        "decode": decode_pct,
    }

    # ---- unicode family ----
    encoders["bu"] = {
        "family": "unicode", "desc": r"\u UNICODE, e.g. \u9090\ueb77...",
        "regex": re.compile(r"(?:\\u[0-9A-Fa-f]{4}){2,}"),
        "decode": decode_bu,
    }
    encoders["pu"] = {
        "family": "unicode", "desc": "%u UNICODE, e.g. %u9090%ueb77...",
        "regex": re.compile(r"(?:%u[0-9A-Fa-f]{4}){2,}"),
        "decode": decode_pu,
    }

    # ---- ascii-decimal family ----
    encoders["dec"] = {
        "family": "ascii",
        "desc": "decimal numbers, arbitrary separator, e.g. 80;75;3;4 or 80-75-3-4",
        "regex": re.compile(r"\d{1,3}(?:\D{1,3}\d{1,3}){3,}"),
        "decode": decode_ascii_dec,
    }

    # ---- binary family (special handling) ----
    encoders["bin"] = {
        "family": "binary",
        "desc": "raw 0/1 string, tested as 7/8-bit chunks with bit-offset skips",
        "regex": re.compile(r"[01]{16,}"),
        "special": "binary",
    }

    # ---- base family (delegated to baseXX.py) ----
    b91_class = _class_regex(BASE91_ALPHABET, minlen)
    b92_alpha = "".join(BASE92_CHARS)
    b92_class = _class_regex(b92_alpha, minlen)
    b45_class = _class_regex(BASE45_ALPHABET, minlen)

    encoders["b32"] = {
        "family": "base", "desc": "Base32 standard (A-Z, 2-7)",
        "regex": _class_regex("A-Z2-7=", minlen), "decode": decode_base32_standard,
    }
    encoders["b32hex"] = {
        "family": "base", "desc": "Base32 Hex (0-9, A-V)",
        "regex": _class_regex("0-9A-Va-v=", minlen), "decode": decode_base32_hex,
    }
    encoders["b32crock"] = {
        "family": "base", "desc": "Base32 Crockford",
        "regex": _class_regex("0-9A-Za-z", minlen), "decode": decode_base32_crockford,
    }
    encoders["b45"] = {
        "family": "base", "desc": "Base45 (RFC 9285)",
        "regex": b45_class, "decode": decode_base45,
    }
    encoders["b58btc"] = {
        "family": "base", "desc": "Base58 Bitcoin alphabet",
        "regex": _class_regex(BASE58_BITCOIN, minlen), "decode": decode_base58_bitcoin,
    }
    encoders["b58flickr"] = {
        "family": "base", "desc": "Base58 Flickr alphabet",
        "regex": _class_regex(BASE58_FLICKR, minlen), "decode": decode_base58_flickr,
    }
    encoders["b58ripple"] = {
        "family": "base", "desc": "Base58 Ripple alphabet",
        "regex": _class_regex(BASE58_RIPPLE, minlen), "decode": decode_base58_ripple,
    }
    encoders["b62"] = {
        "family": "base", "desc": "Base62 (0-9, A-Z, a-z)",
        "regex": _class_regex(BASE62_ALPHABET, minlen), "decode": decode_base62,
    }
    encoders["b36"] = {
        "family": "base", "desc": "Base36 (0-9, A-Z)",
        "regex": _class_regex(BASE36_ALPHABET + string.ascii_lowercase, minlen), "decode": decode_base36,
    }
    encoders["b64"] = {
        "family": "base", "desc": "Base64 standard",
        "regex": re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % minlen), "decode": decode_base64_standard,
    }
    encoders["b64url"] = {
        "family": "base", "desc": "Base64 URL-safe",
        "regex": re.compile(r"[A-Za-z0-9_-]{%d,}={0,2}" % minlen), "decode": decode_base64_urlsafe,
    }
    encoders["b64mime"] = {
        "family": "base", "desc": "Base64 MIME (line-wrapped)",
        "regex": re.compile(r"(?:[A-Za-z0-9+/]{1,76}(?:\r?\n))+[A-Za-z0-9+/]{2,76}={0,2}"),
        "decode": decode_base64_mime,
    }
    encoders["b85a85"] = {
        "family": "base", "desc": "Base85 Ascii85, delimited with <~ ~>",
        "regex": re.compile(r"<~[!-u]{4,}~>"), "decode": decode_base85_ascii85,
    }
    encoders["b85plain"] = {
        "family": "base", "desc": "Base85 Ascii85, no delimiters",
        "regex": re.compile(r"[!-u]{%d,}" % minlen), "decode": decode_base85_plain,
    }
    encoders["b85rfc"] = {
        "family": "base", "desc": "Base85 RFC1924 (Python btoa / ZeroMQ)",
        "regex": _class_regex("0-9A-Za-z!#$%&()*+\\-;<=>?@^_`{|}~", minlen),
        "decode": decode_base85_rfc1924,
    }
    encoders["b91"] = {
        "family": "base", "desc": "Base91",
        "regex": b91_class, "decode": decode_base91,
    }
    encoders["b92"] = {
        "family": "base", "desc": "Base92",
        "regex": b92_class, "decode": decode_base92,
    }

    return encoders


FAMILIES = ("hex", "unicode", "ascii", "binary", "base")


# ─────────────────────────────────────────────
# SCANNING
# ─────────────────────────────────────────────

def scan(text, name, spec, min_decoded_len):
    results = []
    regex = spec["regex"]

    if spec.get("special") == "binary":
        for m in regex.finditer(text):
            for enc_name, decoded in decode_binary_candidates(m.group(0), min_decoded_len):
                results.append({
                    "encoder": enc_name, "family": "binary",
                    "offset": m.start(), "encoded": m.group(0), "decoded": decoded,
                })
        return results

    decode = spec["decode"]
    for m in regex.finditer(text):
        s = m.group(0)
        decoded = decode(s)
        if decoded is None:
            continue
        if not is_printable(decoded):
            continue
        if len(decoded) < min_decoded_len:
            continue
        results.append({
            "encoder": name, "family": spec["family"],
            "offset": m.start(), "encoded": s, "decoded": decoded,
        })
    return results


def truncate(s, full):
    if full or len(s) <= TRUNC:
        return s
    return s[:TRUNC] + "..."


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def select_encoders(all_encoders, encoding_arg, decoders_arg):
    if decoders_arg:
        names = [n.strip() for n in re.split(r"[,;]", decoders_arg) if n.strip()]
        unknown = [n for n in names if n not in all_encoders]
        if unknown:
            cprint("red", f"  Warning: unknown decoder(s) ignored: {', '.join(unknown)}")
        return [n for n in names if n in all_encoders]

    arg = encoding_arg.strip()
    if arg == "all":
        return list(all_encoders.keys())
    if arg in FAMILIES:
        return [k for k, v in all_encoders.items() if v["family"] == arg]

    names = [n.strip() for n in re.split(r"[,;]", arg) if n.strip()]
    unknown = [n for n in names if n not in all_encoders]
    if unknown:
        cprint("red", f"  Warning: unknown encoder(s) ignored: {', '.join(unknown)}")
    return [n for n in names if n in all_encoders]


def main():
    parser = argparse.ArgumentParser(
        description="Extract and decode hex/baseXX/ascii/binary/unicode encoded data from a file.",
    )
    parser.add_argument("file", nargs="?", help="file to scan")
    parser.add_argument("-e", "--encoding", default="all",
                         help="encoder, family (hex/unicode/ascii/binary/base), or 'all' (default: all)")
    parser.add_argument("-E", "--decoders", dest="decoders", default="",
                         help="comma/semicolon separated list of encoders to load (overrides -e)")
    parser.add_argument("-u", "--unique", action="store_true",
                         help="do not repeat identical decoded data")
    parser.add_argument("--full", action="store_true",
                         help="show full encoded/decoded strings instead of truncating to 60 chars")
    parser.add_argument("--minlen", type=int, default=8,
                         help="minimum length of a candidate encoded string (default: 8)")
    parser.add_argument("--mindecoded", type=int, default=3,
                         help="minimum length of decoded output to keep (default: 3)")
    parser.add_argument("--jsonoutput", nargs="?", const="__default__", default=None,
                         metavar="FILE",
                         help="write full, untruncated results as JSON to FILE "
                              "(default: <input>.baseXXdump.json)")
    parser.add_argument("-l", "--list", action="store_true",
                         help="list available encoders and exit")
    args = parser.parse_args()

    all_encoders = build_encoders(args.minlen)

    if args.list:
        cprint("bold", "\n  Available encoders:\n")
        for fam in FAMILIES:
            cprint("cyan", f"  [{fam}]")
            for name, spec in all_encoders.items():
                if spec["family"] == fam:
                    print(f"    {name:<10} {spec['desc']}")
            print()
        return 0

    if not args.file:
        parser.print_help()
        return 1

    if not os.path.isfile(args.file):
        cprint("red", f"  Error: file not found: {args.file}")
        return 1

    with open(args.file, "rb") as f:
        raw = f.read()
    # latin-1 preserves a 1:1 byte<->char mapping so every regex sees all 256 byte values
    text = raw.decode("latin-1")

    selected = select_encoders(all_encoders, args.encoding, args.decoders)
    if not selected:
        cprint("red", "  Error: no valid encoders selected.")
        return 1

    cprint("bold", f"\n{'═' * 70}")
    cprint("cyan", f"  File    : {args.file}  ({len(raw)} bytes)")
    cprint("cyan", f"  Encoders: {', '.join(selected)}")
    cprint("bold", f"{'═' * 70}\n")

    all_results = []
    for name in selected:
        spec = all_encoders[name]
        all_results.extend(scan(text, name, spec, args.mindecoded))

    all_results.sort(key=lambda r: r["offset"])

    seen = set()
    shown = []
    for r in all_results:
        if args.unique:
            if r["decoded"] in seen:
                continue
            seen.add(r["decoded"])
        shown.append(r)

    if not shown:
        cprint("red", "  ✗ No valid decoding found.\n")
    else:
        for r in shown:
            cprint("green", f"  ✓ [{r['family']}] {r['encoder']}  @offset {r['offset']}")
            cprint("magenta", f"    encoded → {truncate(r['encoded'], args.full)}")
            cprint("yellow", f"    decoded → {truncate(r['decoded'], args.full)}")
            print()
        cprint("bold", f"  → {len(shown)} result(s) found\n")

    if args.jsonoutput is not None:
        out_path = args.jsonoutput
        if out_path == "__default__":
            base = os.path.basename(args.file)
            out_path = f"{base}.baseXXdump.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(shown, f, indent=2, ensure_ascii=False)
        cprint("cyan", f"  Full JSON results written to: {out_path}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())