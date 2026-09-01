#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression tests for hashwho.

Run:  pytest -q          (or)   python test_hashwho.py

The EXAMPLES table uses canonical hashcat example hashes (or minimal valid
prefixes for pure-structural rules). Each row asserts that the expected type
appears among the candidates with the expected confidence - this locks
behaviour when the JSON catalogue grows.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hashwho as m  # noqa: E402


# (hash, expected type name, expected confidence)
EXAMPLES = [
    # --- raw digests via length buckets (top bucket entry -> medium) ---
    ("5f4dcc3b5aa765d61d8327deb882cf99", "MD5", "medium"),
    ("8846f7eaee8fb117ad06bdd830b7586c", "NTLM (NT hash)", "low"),
    ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "SHA1", "medium"),
    ("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "SHA-256", "medium"),
    ("b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb9"
     "80b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "SHA-512", "medium"),
    ("cbfdac6008f9cab4083784cbd1874f76618d2a97", "RIPEMD-160", "low"),
    # --- structural (always high) ---
    ("$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", "bcrypt ($2*$)", "high"),
    ("$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnP"
     "gh2XzzF0NDrUhgrcLwg78xikPmb5C0js9AQ.", "sha512crypt ($6$)", "high"),
    ("$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD",
     "sha256crypt ($5$)", "high"),
    ("$1$28772684$iEwNOgGugqO9.bIz5sk8k/", "md5crypt ($1$)", "high"),
    ("$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.", "Apache apr1 ($apr1$)", "high"),
    ("$P$984478476IagS59wHZvyQMArzfx58u.", "phpass (WP/phpBB3)", "high"),
    ("$S$C33783772bRXEx1aCsvY.dqgd9xA/iktKuqcMe3xdZq1i5ykRcbG", "Drupal7 ($S$)", "high"),
    ("$krb5tgs$23$*user$realm$test/spn*$abcd$ef01", "Kerberos 5 TGS-REP (23)", "high"),
    ("$krb5asrep$23$user@realm:abcd$ef01", "Kerberos 5 AS-REP (23)", "high"),
    ("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", "MySQL 4.1+/5 (SHA1x2)", "high"),
    ("{SSHA}uWg1PgO/8Yj6Dce+64GwV8ZTGkNjX1lp", "LDAP {SSHA}", "high"),
    ("{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "LDAP {SHA}", "high"),
    ("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6ImFkbWluIn0."
     "8hLdG5wZC4iEr8dNzXjIB4V4X7bO0mQXhP1v6mIzbEk", "JWT (HS256/384/512)", "high"),
    ("$pbkdf2-sha256$29000$Zsjm2Ztb61WSchLC2Ptfaw$prOKZQVBk...", "PBKDF2-HMAC-SHA256", "high"),
    ("$argon2id$v=19$m=65536,t=3,p=1$abc$def", "Argon2", "high"),
    ("pbkdf2_sha256$260000$abcdefgh$Zm9vYmFyYmF6", "Django PBKDF2-SHA256", "high"),
    # --- salted combos ---
    ("098f6bcd4621d373cade4e832627b4f6:mysalt",
     "md5($pass.$salt) / md5($salt.$pass)", "medium"),
    ("2fdeb14a0e17a12250e276237261d059e0f987fe:mysalt",
     "sha1($pass.$salt) / sha1($salt.$pass)", "high"),
]


def _names(h):
    return [n for n, _ in m.identify(h)[1]]


def _conf(h, name):
    return dict(m.identify(h)[1]).get(name)


def test_examples():
    bad = []
    for h, want, conf in EXAMPLES:
        got = _conf(h, want)
        if got != conf:
            bad.append(f"{want!r}: want {conf}, got {got}  ({h[:40]})")
    assert not bad, "\n".join(bad)


def test_descrypt_is_low_and_last():
    r = m.identify("5f4dcc3b5aa76")[1]          # 13 hex chars
    assert r and r[-1][0] == "descrypt (DES)" and r[-1][1] == "low"
    # not offered for a 32-char hash
    assert "descrypt (DES)" not in _names("5f4dcc3b5aa765d61d8327deb882cf99")


def test_no_phantom_type_references():
    known = set(m.TYPES) | set(m.EXTRA)
    ref = set()
    for names in m.HEX_BUCKETS.values():
        ref |= set(names)
    for names in m.B64_BUCKETS.values():
        ref |= set(names)
    for _, names, _ in m.STRUCTURAL:
        ref |= set(names)
    for _, names in m.SALTED:
        ref |= set(names)
    assert ref <= known, f"unknown catalogue refs: {sorted(ref - known)}"


def test_cisco7_decode():
    assert m.cisco7_decode("02050D480809") == "cisco"
    assert m.cisco7_decode("deadbeef") is None            # bad offset digits
    assert "Cisco type 7" in _names("02050D480809")


def test_jwt_decode():
    tok = ("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6ImFkbWluIn0.sig")
    hdr, pl = m.jwt_decode(tok)
    assert hdr["alg"] == "HS256" and pl["login"] == "admin"
    assert m.jwt_decode("not.a.jwt") is None


def test_base64_digest_to_hex():
    # base64 of raw MD5("password")
    assert m.b64_to_hex("X03MO1qnZdYdgyfeuILPmQ==") == "5f4dcc3b5aa765d61d8327deb882cf99"


def test_normalize():
    assert m._normalize('"5f4dcc3b5aa765d61d8327deb882cf99"') == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert m._normalize("`abc`") == "abc"
    assert m._normalize("$HEX[4142]") == "AB"


def test_hex_wrapped_salt_field():
    md5 = "098f6bcd4621d373cade4e832627b4f6"
    h = md5 + ":$HEX[7c21]"                      # salt = bytes 0x7c 0x21 = "|!"
    # detection still classifies it as salted md5
    assert "md5($pass.$salt) / md5($salt.$pass)" in _names(h)
    # and the salt is decoded for the report / JSON
    assert m.decode_hex_fields(h) == [(1, "$HEX[7c21]", "|!")]
    # non-printable bytes shown as \xNN, string stays one line
    assert m.decode_hex_fields(md5 + ":$HEX[0a00ff]") == [(1, "$HEX[0a00ff]", "\\x0a\\x00\\xff")]
    assert m.decode_hex_fields(md5) == []
    # long hex salt (>64 chars) is still classified after the bound bump
    assert "md5($pass.$salt) / md5($salt.$pass)" in _names(md5 + ":" + "ab" * 60)


def test_multi_positional_inputs():
    args = m.build_parser().parse_args(["h1", "h2", "h3"])
    assert list(m.iter_inputs(args)) == ["h1", "h2", "h3"]
    # '-' inside the list is a stdin marker, not a literal hash
    args = m.build_parser().parse_args(["x"])
    assert list(m.iter_inputs(args)) == ["x"]


def test_data_file_loads():
    t, e, s, sa, hb, bb = m._load_data()
    assert t and s and sa and hb and bb
    assert all(len(v) == 3 for v in t.values())


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    fails = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except AssertionError as ex:
            fails += 1
            print(f"FAIL {fn.__name__}\n     {ex}")
    print(f"\n{len(fns) - fails}/{len(fns)} passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(_run())
