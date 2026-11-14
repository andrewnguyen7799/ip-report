#!/usr/bin/env python3
"""Encrypt / decrypt the stats data for the password-protected page.

  python3 tools/crypt.py encrypt data.plain.json data.enc.json   (password from env IP_PASS)
  python3 tools/crypt.py decrypt data.enc.json data.plain.json

AES-256-GCM, key = PBKDF2-HMAC-SHA256(password, salt, 200000). Matches index.html (WebCrypto).
"""
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 200000

def key(pw, salt, it=ITER):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(pw.encode())

def main():
    mode, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    pw = os.environ.get("IP_PASS")
    if not pw:
        sys.exit("set IP_PASS")
    if mode == "encrypt":
        data = json.load(open(src, encoding="utf8"))
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
        salt, iv = os.urandom(16), os.urandom(12)
        ct = AESGCM(key(pw, salt)).encrypt(iv, raw, None)
        b = lambda x: base64.b64encode(x).decode()
        json.dump({"v": 1, "iter": ITER, "salt": b(salt), "iv": b(iv), "ct": b(ct)}, open(dst, "w"))
    elif mode == "decrypt":
        e = json.load(open(src))
        d = lambda x: base64.b64decode(x)
        raw = AESGCM(key(pw, d(e["salt"]), e["iter"])).decrypt(d(e["iv"]), d(e["ct"]), None)
        json.dump(json.loads(raw), open(dst, "w", encoding="utf8"), ensure_ascii=False, indent=1)
    else:
        sys.exit("mode must be encrypt or decrypt")

if __name__ == "__main__":
    main()
