# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-01

Initial public release.

### Added
- Data-driven catalogue in `hashwho_data.json`: 113 hash types, 78 structural
  rules, salted-combo patterns, and hex/base64 length buckets. Adding a type is
  a JSON edit, no code change.
- Layered detection: structural regex (first-char gated) -> salted combos ->
  length buckets -> reversible schemes -> descrypt (always last, always low).
- `hashcat -m` and `john --format=` lookup; `--cmd` prints full command lines.
- Decoders: Cisco IOS type 7 (reported only when it decodes to printable text),
  JWT header/claims, base64 raw digest -> hex, hashcat `$HEX[...]` salt fields.
- Input handling: multiple hashes as positional args, `-f/--file`, stdin (`-`),
  `-u/--unique`, `-s/--strip-user`, quote/`$HEX[...]` normalization.
- Output modes: coloured report, `-b/--brief`, `-1/--first`, `--json` (JSONL),
  `--mode` (top hashcat mode only, for scripting).
- Regression test suite (`test_hashwho.py`), runnable with or without pytest.

### Known limitations
- `john --format=` names for ~40 rarer types are unverified against John-Jumbo.
- Multi-mode types (Office/PDF/Kerberos 17-18/MongoDB/DPAPI) are not
  disambiguated; `--mode` returns the first mode in the list.
- No hash extraction from binary files.
