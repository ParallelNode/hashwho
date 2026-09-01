# hashwho

**Identify a hash by length, charset and structure — then get the exact `hashcat -m` / `john --format=` command to crack it.**

`hashwho` is a single-file, zero-dependency CLI in the spirit of
[name-that-hash](https://github.com/HashPals/Name-That-Hash) and
[haiti](https://github.com/noraj/haiti). It classifies a hash against a
data-driven catalogue of **113 hash types** (126 counting decode-only helpers)
and **78 structural rules**, ranks the candidates by confidence, and prints
copy-paste-ready cracking commands.

---

## Install

**Run it directly** (needs only Python ≥ 3.8, no third-party packages):

```sh
git clone https://github.com/ParallelNode/hashwho
cd hashwho
python hashwho.py 5f4dcc3b5aa765d61d8327deb882cf99
```

**Or install the `hashwho` command** into your environment:

```sh
pip install git+https://github.com/ParallelNode/hashwho
```

`hashwho.py` and `hashwho_data.json` must stay side by side — the catalogue is
loaded at runtime and the tool exits with an error if it is missing. `pip
install` handles that for you.

---

## Usage

### Single hash

```
$ hashwho 5f4dcc3b5aa765d61d8327deb882cf99
hash: 5f4dcc3b5aa765d61d8327deb882cf99
len=32  charset=hex (lower)

[medium] MD5   (hashcat -m 0 | john raw-md5)
[low]    NTLM (NT hash)   (hashcat -m 1000 | john nt)
          - Windows NT hash
[low]    MD4   (hashcat -m 900 | john raw-md4)
[low]    LM   (hashcat -m 3000 | john lm)
          - uppercased, <=14 chars, often split A:B
[low]    MD2
[low]    RAdmin v2.x   (hashcat -m 9900)
```

### Structural match + full commands

```
$ hashwho '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy' --cmd -w rockyou.txt
hash: $2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
len=60  charset=printable

[high]   bcrypt ($2*$)   (hashcat -m 3200 | john bcrypt)
          $ hashcat -m 3200 -a 0 hash.txt rockyou.txt
          $ john --format=bcrypt --wordlist=rockyou.txt hash.txt
```

### Reversible encodings are decoded, not cracked

```
$ hashwho 02050D480809
[high]   Cisco type 7
          - reversible XOR, decode not crack
          decoded: cisco
```

`hashwho` also decodes JWT headers/claims and re-emits base64 raw digests as hex.

### Many hashes at once

Pass several as positional arguments, or one per line via `-f file` / stdin.
`--first` keeps one tab-separated line per hash:

```
$ hashwho 5f4dcc3b5aa765d61d8327deb882cf99 02050D480809 '$1$28772684$iEwNOgGugqO9.bIz5sk8k/' --first
5f4dcc3b5aa765d61d8327deb882cf99          MD5              0     raw-md5
02050D480809                              Cisco type 7     -     -
$1$28772684$iEwNOgGugqO9.bIz5sk8k/       md5crypt ($1$)   500   md5crypt
```

### Scripting

```sh
# JSONL, one object per hash
hashwho -f dump.txt --unique --json | jq .

# resolve the top hashcat mode and feed it straight into hashcat
hashcat -m "$(hashwho --mode 5f4dcc3b5aa765d61d8327deb882cf99)" -a 0 hash.txt rockyou.txt
```

### Options

| Flag | Purpose |
|------|---------|
| `-f, --file FILE` | one hash per line |
| `-c, --cmd` | print full hashcat/john command lines |
| `-w, --wordlist` / `-H, --hashfile` | values to embed in those commands |
| `-a, --all` / `-t, --top N` | show all / first N candidates (default 6) |
| `-u, --unique` | skip duplicates in file/stdin mode |
| `-s, --strip-user` | drop a leading `username:` (pwdump / `:`-separated dumps) |
| `-b, --brief` | one tab-separated line per candidate: `hash<TAB>name<TAB>hashcat<TAB>john` |
| `-1, --first` | brief output, top candidate only |
| `--json` | JSONL output (one object per hash) |
| `--mode` | print only the top `hashcat -m` number and exit |
| `--no-color` | disable ANSI colour |

---

## How it works

Detection is layered, most-specific first:

1. **Structural regex** — prefix/format signatures (`$2y$`, `$krb5tgs$`, `{SSHA}`,
   `pbkdf2_sha256$…`). Always high confidence. Indexed by first character so
   only the relevant handful of rules run per hash.
2. **Salted combos** — `hex:salt` shapes for `md5($pass.$salt)` & friends.
3. **Length buckets** — raw hex digests grouped by length
   (8/16/32/40/56/64/96/128) and base64 digests by decoded byte length
   (16/20/28/32/48/64). Medium/low confidence; the most common type in each
   bucket is ranked first.
4. **Reversible schemes** — Cisco type 7 is reported only if it actually decodes
   to printable text.
5. **descrypt** — any 13-char `crypt(3)` string; always last, always low, since
   it has no distinguishing structure.

### Adding a hash type

Edit `hashwho_data.json` — no code change. Schema:

```jsonc
"types":     { "MD5": [0, "raw-md5", null] },        // name -> [hashcat_mode, john_format, note]
"structural":[ { "pattern": "^\\$2[aby]\\$", "names": ["bcrypt ($2*$)"], "gate": "$" } ],
"salted":    [ { "pattern": "^[a-f0-9]{32}:[^:\\s]{1,256}$", "names": ["md5($pass.$salt) / md5($salt.$pass)"] } ],
"hex_buckets":{ "32": ["MD5", "NTLM (NT hash)", "..."] },
"b64_buckets":{ "16": ["MD5 (base64)", "..."] }
```

---

## vs. other identifiers

| | hashwho | name-that-hash | haiti | hashID |
|---|---|---|---|---|
| Language | Python, **stdlib only** | Python + deps | Ruby | Python |
| hashcat `-m` numbers | ✅ | ✅ | ✅ | ✅ |
| john `--format=` names | ✅ (see caveat) | ✅ | ✅ | partial |
| Ready-to-run command lines | ✅ | ✅ | ✅ | ✅ |
| Decodes Cisco 7 / JWT / base64→hex | ✅ | ✅ (partial) | ❌ | ❌ |
| Multi-hash / file / stdin / JSONL | ✅ | ✅ | ✅ | ✅ |
| Drop-in, no install / no deps | ✅ | ❌ | ❌ | ✅ |

---

## Known limitations

- **John format names for the less common types are unverified.** The hashcat
  mode numbers are standard and checked; the `--format=` names for ~40 of the
  rarer types (e.g. `grub-pbkdf2-sha512`, `mongodb-scram`, `itunes-backup`) were
  filled in from documentation but not tested against a real John-Jumbo build.
  A wrong name just makes John print *"Unknown ciphertext format"* — no data
  loss. Corrections welcome.
- **Multi-mode types are not disambiguated.** Office / PDF / Kerberos etype
  17-18 / MongoDB / DPAPI carry a slash-list of modes; `--mode` returns the
  first one. Read the internal version field yourself if it matters.
- **No hash extraction from binary files.** `hashwho` identifies strings; use
  `7z2john` / `keepass2john` / `bitcoin2john` to produce the string first.
- Identification is probabilistic: several algorithms share a length and
  charset. Confidence tags reflect that.

---

## Tests

```sh
python test_hashwho.py     # no dependencies
# or
pytest -q
```

---

## License

[MIT](LICENSE)
