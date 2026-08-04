# baseXXdump.py

Multi-format encoded-data extractor and decoder for CTF file analysis.

Scans a file for candidate encoded blobs — hex variants, baseXX strings, separated ASCII-decimal, raw binary (0/1), and unicode-escaped bytes — and tries to decode every candidate into readable text. Fully self-contained: no external dependencies, no sibling files required.

## Features

- **Hex family**: plain hex, `\x`, `&H`, comma-separated `0x`, big/little-endian `0x` grouping, percent-hex (`%XX`)
- **Unicode family**: `\uXXXX` and `%uXXXX` (2 bytes per token)
- **ASCII family**: decimal byte values with arbitrary separators (`;`, `-`, space, ...)
- **Binary family**: raw `0`/`1` strings, brute-forced across 7-bit and 8-bit chunking with all bit-offset skips
- **Base family**: Base32 (standard / hex / Crockford), Base36, Base45, Base58 (Bitcoin / Flickr / Ripple), Base62, Base64 (standard / URL-safe / MIME), Base85 (Ascii85 delimited / plain / RFC1924), Base91, Base92
- Filters candidates by printable-ratio, deduplicates identical decoded output, and can dump full untruncated results to JSON

## Requirements

- Python 3.6+
- No third-party packages, no external files needed

## Usage

```bash
python3 baseXXdump.py <file> [options]
```

### Options

| Flag | Description |
|---|---|
| `-e, --encoding` | Encoder, family (`hex`/`unicode`/`ascii`/`binary`/`base`), or `all` (default: `all`) |
| `-E, --decoders` | Comma/semicolon-separated list of specific encoders to load (overrides `-e`) |
| `-u, --unique` | Do not repeat identical decoded output |
| `--full` | Show full encoded/decoded strings instead of truncating to 60 chars |
| `--minlen` | Minimum length of a candidate encoded string (default: 8) |
| `--mindecoded` | Minimum length of decoded output to keep (default: 3) |
| `--jsonoutput [FILE]` | Write full, untruncated results as JSON (default: `<input>.baseXXdump.json`) |
| `-l, --list` | List all available encoders and exit |

## Examples

```bash
# Scan everything, deduplicate identical results
python3 baseXXdump.py firmware.bin -e all -u

# Only scan the hex family (zxbe/zxle/ah/bx/zxc/hex/pct)
python3 baseXXdump.py dump.bin -e hex

# Target specific decoders
python3 baseXXdump.py dump.bin -E b64,b58btc,dec

# Full (non-truncated) console output
python3 baseXXdump.py dump.bin --full

# Export complete results to JSON
python3 baseXXdump.py dump.bin --jsonoutput

# List every supported encoder
python3 baseXXdump.py -l
```

## Available encoders

[hex] hex, bx, ah, zxc, zxbe, zxle, pct
[unicode] bu, pu
[ascii] dec
[binary] bin
[base] b32, b32hex, b32crock, b45, b58btc, b58flickr, b58ripple, b62, b36, b64, b64url, b64mime, b85a85, b85plain, b85rfc, b91, b92

## Notes

- Broad-alphabet base decoders (`b58*`, `b62`, `b91`, `b92`) can overlap and produce false positives on dense binary data — this is expected brute-force scanner behavior, not a bug. Tune `--minlen` / `--mindecoded` to reduce noise.
- The `binary` family always emits 16 candidates per match (2 widths × 8 bit-offsets); only one is typically the correct decoding, the rest are noise by design.