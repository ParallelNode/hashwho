#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashwho - identify a hash by length, charset and structure, and emit
ready-to-run hashcat / john commands.

Single file, standard library only. The hash-type catalogue and the
detection rules live in hashwho_data.json, next to this script.

    hashwho <hash> [<hash> ...]
    hashwho -f dump.txt --json
    hashcat -m "$(hashwho --mode <hash>)" -a 0 hash.txt rockyou.txt

See --help for all options.
"""

__version__ = "1.0.0"

import argparse
import base64
import binascii
import functools
import json
import os
import re
import sys

# --------------------------------------------------------------------------- #
#  Hash type catalogue.  name -> (hashcat_mode, john_format, note)
# --------------------------------------------------------------------------- #
#  Catalogue + detection prototypes live in an external JSON file
#  (hashwho_data.json, next to this script) so the ruleset can grow without
#  code changes.  Schema:
#    types / extra : { name: [hashcat_mode|null, john_format|null, note|null] }
#    structural    : [ { "pattern": str, "names": [str], "gate": str|null } ]
#    salted        : [ { "pattern": str, "names": [str] } ]
#    hex_buckets   : { "<hex length>": [name, ...] }
#    b64_buckets   : { "<decoded byte length>": [name, ...] }
# --------------------------------------------------------------------------- #
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hashwho_data.json")


def _load_data(path=DATA_FILE):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
    except FileNotFoundError:
        sys.exit(f"error: catalogue file not found: {path}")
    except (OSError, ValueError) as e:
        sys.exit(f"error: cannot read catalogue {path}: {e}")

    rx = lambda p: re.compile(p, re.IGNORECASE)
    return (
        {k: tuple(v) for k, v in d.get("types", {}).items()},
        {k: tuple(v) for k, v in d.get("extra", {}).items()},
        [(rx(e["pattern"]), e["names"], e["gate"]) for e in d.get("structural", [])],
        [(rx(e["pattern"]), e["names"]) for e in d.get("salted", [])],
        {int(k): v for k, v in d.get("hex_buckets", {}).items()},
        {int(k): v for k, v in d.get("b64_buckets", {}).items()},
    )


TYPES, EXTRA, STRUCTURAL, SALTED, HEX_BUCKETS, B64_BUCKETS = _load_data()


def _index_structural():
    """Bucket STRUCTURAL by gate char so identify() only tries the relevant few."""
    ungated, by_gate = [], {}
    for rx, names, gate in STRUCTURAL:
        if gate is None:
            ungated.append((rx, names))
        else:
            for ch in gate:
                by_gate.setdefault(ch, []).append((rx, names))
    return ungated, by_gate


_STRUCT_UNGATED, _STRUCT_BY_GATE = _index_structural()

# descrypt has no real structural signature - *any* 13-char crypt(3)-alphabet
# string is a valid candidate - so it is only ever a low-confidence guess,
# checked last and kept out of STRUCTURAL to avoid a bogus [high] tag.
DESCRYPT_RX = re.compile(r'^[./A-Za-z0-9]{13}$')

# Cisco IOS "type 7": 2-digit key offset + hex body, XORed against a fixed key.
# Reversible - decoded, not cracked.
CISCO7_RX = re.compile(r'^\d{2}[0-9A-Fa-f]{4,}$')
_CISCO7_KEY = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"


def cisco7_decode(h):
    """Decode a Cisco IOS type-7 string. Return plaintext, or None if it is not
    a valid type-7 (bad offset / odd hex / non-printable result)."""
    if len(h) < 4 or not h[:2].isdigit():
        return None
    off, body = int(h[:2]), h[2:]
    if off >= len(_CISCO7_KEY) or len(body) % 2:
        return None
    try:
        raw = bytes.fromhex(body)
    except ValueError:
        return None
    out = "".join(chr(b ^ ord(_CISCO7_KEY[(off + i) % len(_CISCO7_KEY)]))
                  for i, b in enumerate(raw))
    if any(ord(c) < 32 or ord(c) > 126 for c in out):
        return None
    return out




# --------------------------------------------------------------------------- #
#  Colour helpers (auto-off when not a TTY or NO_COLOR set).
# --------------------------------------------------------------------------- #
class C:
    enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    @classmethod
    def _w(cls, code, s): return f"\033[{code}m{s}\033[0m" if cls.enabled else s
    @classmethod
    def bold(cls, s):   return cls._w("1", s)
    @classmethod
    def dim(cls, s):    return cls._w("2", s)
    @classmethod
    def orange(cls, s): return cls._w("38;5;208", s)
    @classmethod
    def green(cls, s):  return cls._w("32", s)
    @classmethod
    def cyan(cls, s):   return cls._w("36", s)
    @classmethod
    def red(cls, s):    return cls._w("31", s)


# --------------------------------------------------------------------------- #
#  Charset analysis - report the tightest single classification.
# --------------------------------------------------------------------------- #
@functools.lru_cache(maxsize=256)
def analyse_charset(h):
    if re.fullmatch(r'[0-9a-f]+', h):            return "hex (lower)"
    if re.fullmatch(r'[0-9A-F]+', h):            return "hex (upper)"
    if re.fullmatch(r'[0-9a-fA-F]+', h):         return "hex (mixed)"
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', h): return "base64"
    if re.fullmatch(r'[A-Za-z0-9._/+=$-]+', h):  return "printable"
    return "other"


def b64_decode_bytes(h):
    """Return decoded bytes if h is valid base64 (std or urlsafe), else None."""
    s = h + "=" * (-len(h) % 4)
    for altchars in (None, b"-_"):
        try:
            return base64.b64decode(s, altchars=altchars, validate=True)
        except (binascii.Error, ValueError):
            continue
    return None


def b64_decoded_len(h):
    """Return decoded byte length if h is valid base64 (std or urlsafe), else None."""
    b = b64_decode_bytes(h)
    return len(b) if b is not None else None


def b64_to_hex(h):
    """Hex of the raw bytes behind a base64 digest - ready to paste into hashcat."""
    b = b64_decode_bytes(h)
    return b.hex() if b is not None else None


def jwt_decode(h):
    """Return (header, payload) dicts of a JWT (no signature check), else None."""
    parts = h.split(".")
    if len(parts) != 3:
        return None
    try:
        hdr = json.loads(b64_decode_bytes(parts[0]) or b"")
        pl = json.loads(b64_decode_bytes(parts[1]) or b"")
    except (ValueError, TypeError):
        return None
    if not isinstance(hdr, dict):
        return None
    return hdr, (pl if isinstance(pl, dict) else {})


# --------------------------------------------------------------------------- #
#  Identification core
# --------------------------------------------------------------------------- #
_QUOTES = ("'", '"', "`")


def _normalize(h):
    """Trim whitespace, unwrap matched quotes, expand hashcat's $HEX[...]."""
    h = h.strip()
    while len(h) >= 2 and h[0] in _QUOTES and h[-1] == h[0]:
        h = h[1:-1].strip()
    m = re.fullmatch(r'\$HEX\[([0-9A-Fa-f]*)\]', h)
    if m and len(m.group(1)) % 2 == 0:
        try:
            b = bytes.fromhex(m.group(1))
        except ValueError:
            b = b""
        if b and all(32 <= c < 127 for c in b):
            h = b.decode("ascii")
    return h


_HEX_FIELD_RX = re.compile(r'^\$HEX\[([0-9A-Fa-f]*)\]$')


def decode_hex_fields(h):
    """hashcat wraps a salt/field in $HEX[..] when it holds odd bytes.
    Return [(field_index, raw_token, readable_repr), ...] for every such field.
    Non-printable bytes are shown as \\xNN so the string stays single-line."""
    if ":" not in h:
        return []
    out = []
    for i, f in enumerate(h.split(":")):
        m = _HEX_FIELD_RX.match(f)
        if not m or len(m.group(1)) % 2:
            continue
        try:
            b = bytes.fromhex(m.group(1))
        except ValueError:
            continue
        rep = "".join(chr(c) if 32 <= c < 127 else f"\\x{c:02x}" for c in b)
        out.append((i, f, rep))
    return out


def identify(h):
    """Return (clean_hash, [(name, confidence), ...])."""
    h = _normalize(h)
    results, seen = [], set()

    def add(name, conf):
        if name not in seen:
            seen.add(name)
            results.append((name, conf))

    first = h[:1]

    # 1. structural (high) - only the gate-matching subset, then the ungated ones
    for rx, names in _STRUCT_BY_GATE.get(first, ()):
        if rx.match(h):
            for n in names:
                add(n, "high")
    for rx, names in _STRUCT_UNGATED:
        if rx.match(h):
            for n in names:
                add(n, "high")

    # 2. salted combos
    for rx, names in SALTED:
        if rx.match(h):
            for n in names:
                add(n, "high" if len(names) == 1 else "medium")

    charset = analyse_charset(h)
    is_hex = charset.startswith("hex")

    # 3. generic hex buckets
    if is_hex:
        for i, n in enumerate(HEX_BUCKETS.get(len(h), [])):
            add(n, "medium" if i == 0 else "low")

    # 4. base64 raw digests (only when not plain hex, to avoid double-flagging)
    elif charset == "base64":
        blen = b64_decoded_len(h)
        if blen in B64_BUCKETS:
            for i, n in enumerate(B64_BUCKETS[blen]):
                add(n, "medium" if i == 0 else "low")

    # 5. Cisco IOS type 7 - only report when it actually decodes to printable text
    if CISCO7_RX.match(h) and cisco7_decode(h) is not None:
        add("Cisco type 7", "high")

    # 6. descrypt - always last, always low (no distinguishing structure)
    if DESCRYPT_RX.match(h):
        add("descrypt (DES)", "low")

    return h, results


# --------------------------------------------------------------------------- #
#  Command rendering
# --------------------------------------------------------------------------- #
def lookup(name):
    return TYPES.get(name) or EXTRA.get(name) or (None, None, None)


def top_mode(results):
    """First candidate with a usable numeric hashcat mode (for --mode)."""
    for name, _ in results:
        mode = lookup(name)[0]
        if mode:
            return mode.split("/")[0].strip()
    return None


def hashcat_cmd(name, hashfile, wordlist):
    mode = lookup(name)[0]
    return f"hashcat -m {mode} -a 0 {hashfile} {wordlist}" if mode else None


def john_cmd(name, hashfile, wordlist):
    fmt = lookup(name)[1]
    if not fmt:
        return None
    wl = f" --wordlist={wordlist}" if wordlist != "<wordlist>" else ""
    return f"john --format={fmt}{wl} {hashfile}"


CONF_TAG = {
    "high":   lambda: C.green("[high]  "),
    "medium": lambda: C.orange("[medium]"),
    "low":    lambda: C.dim("[low]   "),
}


def conf_tag(conf):
    """Coloured confidence label; tolerate unknown values instead of KeyError."""
    fn = CONF_TAG.get(conf)
    return fn() if fn else C.dim(f"[{conf}]".ljust(8))


def report(raw, results, args):
    print(C.bold(C.orange("hash: ")) + raw)
    print(C.dim(f"len={len(raw)}  charset={analyse_charset(raw)}"))
    for idx, tok, rep in decode_hex_fields(raw):
        print(C.dim(f"field {idx} {tok} = ") + C.bold(rep))
    print()
    if not results:
        print(C.red("No match. Unusual length/charset, encrypted blob, or a raw token."))
        return

    shown = results if args.all else results[:args.top]
    for name, conf in shown:
        mode, fmt, note = lookup(name)
        line = f"{conf_tag(conf)} {C.bold(name)}"
        meta = []
        if mode: meta.append(f"hashcat -m {mode}")
        if fmt:  meta.append(f"john {fmt}")
        if meta: line += C.dim("   (" + " | ".join(meta) + ")")
        print(line)
        if note:
            print("          " + C.dim("- " + note))
        if name == "Cisco type 7":
            dec = cisco7_decode(raw)
            if dec is not None:
                print("          " + C.green("decoded: ") + C.bold(dec))
        if name.endswith("(base64)"):
            hx = b64_to_hex(raw)
            if hx is not None:
                print("          " + C.green("hex: ") + C.bold(hx))
        if name.startswith("JWT"):
            jd = jwt_decode(raw)
            if jd:
                hdr, pl = jd
                alg = str(hdr.get("alg", "?"))
                warn = "" if alg.upper().startswith("HS") else "  (not HMAC - nothing to brute-force)"
                print("          " + C.green("alg: ") + alg + C.dim(warn))
                claims = ", ".join(f"{k}={pl[k]}" for k in list(pl)[:6])
                if claims:
                    print("          " + C.dim("claims: " + claims))
        if args.cmd:
            hc = hashcat_cmd(name, args.hashfile, args.wordlist)
            jn = john_cmd(name, args.hashfile, args.wordlist)
            if hc: print("          " + C.cyan("$ " + hc))
            if jn: print("          " + C.cyan("$ " + jn))
            print()

    hidden = len(results) - len(shown)
    if hidden > 0 and not args.all:
        print(C.dim(f"... +{hidden} more (use --all)"))


def brief(raw, results, args):
    """Compact, colour-free, greppable output - minimal tokens for scripts/LLMs."""
    if not results:
        print(f"{raw}\t-\t-\t-")
        return
    shown = results[:1] if args.first else results if args.all else results[:args.top]
    for name, _ in shown:
        mode, fmt, _ = lookup(name)
        print(f"{raw}\t{name}\t{mode or '-'}\t{fmt or '-'}")


def as_json(raw, results):
    jd = jwt_decode(raw) if any(n.startswith("JWT") for n, _ in results) else None
    return {
        "hash": raw,
        "length": len(raw),
        "charset": analyse_charset(raw),
        "candidates": [
            {"name": n, "confidence": c,
             "hashcat": lookup(n)[0], "john": lookup(n)[1], "note": lookup(n)[2]}
            for n, c in results
        ],
        "decoded": (cisco7_decode(raw)
                    if any(n == "Cisco type 7" for n, _ in results) else None),
        "hex": (b64_to_hex(raw)
                if any(n.endswith("(base64)") for n, _ in results) else None),
        "jwt": {"header": jd[0], "payload": jd[1]} if jd else None,
        "hex_fields": [{"index": i, "raw": t, "decoded": r}
                       for i, t, r in decode_hex_fields(raw)] or None,
    }


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def build_parser():
    p = argparse.ArgumentParser(
        prog="hashwho",
        description="Identify a hash by length + charset + pattern and print "
                    "ready-to-copy hashcat / john commands.",
        epilog="examples:\n"
               "  hashwho 5f4dcc3b5aa765d61d8327deb882cf99\n"
               "  hashwho hash1 hash2 hash3 --brief\n"
               "  hashwho '$2y$10$...' --cmd -w rockyou.txt\n"
               "  echo <hash> | hashwho -\n"
               "  hashwho -f dump.txt --unique --json | jq .\n"
               "  hashcat -m $(hashwho --mode <hash>) -a 0 hash.txt rockyou.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-V", "--version", action="version",
                   version=f"%(prog)s {__version__}")
    p.add_argument("hash", nargs="*",
                   help="one or more hash strings (or '-' to read stdin)")
    p.add_argument("-f", "--file", help="file with one hash per line")
    p.add_argument("-c", "--cmd", action="store_true",
                   help="print full hashcat/john command lines for each candidate")
    p.add_argument("-w", "--wordlist", default="<wordlist>",
                   help="wordlist path to embed in the commands")
    p.add_argument("-H", "--hashfile", default="hash.txt",
                   help="hash file name to embed in the commands (default: hash.txt)")
    p.add_argument("-a", "--all", action="store_true", help="show all candidates")
    p.add_argument("-t", "--top", type=int, default=6, help="candidates to show (default: 6)")
    p.add_argument("-u", "--unique", action="store_true",
                   help="in file/stdin mode, skip duplicate hashes")
    p.add_argument("-s", "--strip-user", action="store_true",
                   help="drop a leading 'username:' before the hash (pwdump / :-separated dumps)")
    p.add_argument("--json", action="store_true",
                   help="emit JSONL (one JSON object per hash) instead of text")
    p.add_argument("-b", "--brief", action="store_true",
                   help="one tab-separated line per candidate: hash<TAB>name<TAB>hashcat<TAB>john")
    p.add_argument("-1", "--first", action="store_true",
                   help="brief output, top candidate only")
    p.add_argument("--mode", action="store_true",
                   help="print only the top hashcat -m number (for scripting) and exit")
    p.add_argument("--no-color", action="store_true", help="disable colours")
    return p


def iter_inputs(args):
    def prep(line):
        line = line.strip()
        if args.strip_user and ":" in line:
            line = line.split(":", 1)[1]
        return line

    hashes = args.hash or []

    if args.file:
        with open(args.file, "r", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    yield prep(line)

    stdin_piped = not hashes and not args.file and not sys.stdin.isatty()
    if "-" in hashes or stdin_piped:
        for line in sys.stdin:
            if line.strip():
                yield prep(line)

    for h in hashes:
        if h != "-" and h.strip():
            yield prep(h)


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color:
        C.enabled = False

    stream = iter_inputs(args)

    # --mode: just resolve the first input and print its top mode
    if args.mode:
        first = next(stream, None)
        if first is None:
            print("no input", file=sys.stderr)
            return 2
        _, results = identify(first)
        m = top_mode(results)
        if not m:
            print("no hashcat mode for top candidate", file=sys.stderr)
            return 1
        print(m)
        return 0

    seen = set()
    count = 0
    for h in stream:
        if args.unique:
            if h in seen:
                continue
            seen.add(h)
        raw, results = identify(h)
        if args.json:
            print(json.dumps(as_json(raw, results), ensure_ascii=False))
        elif args.brief or args.first:
            brief(raw, results, args)
        else:
            if count > 0:
                print(C.orange("=" * 60))
            report(raw, results, args)
            print()
        count += 1

    if count == 0:
        build_parser().print_help()
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BrokenPipeError, KeyboardInterrupt):
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(130)