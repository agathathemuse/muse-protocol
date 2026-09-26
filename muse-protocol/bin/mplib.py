"""Shared helpers for the muse-protocol CLI tools (not run directly)."""
import base64
import json
import secrets
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

PROTOCOL = "muse-protocol/1"


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def urlopen_retry(req_or_url, timeout=30, tries=2):
    """urlopen with one retry; egress proxies occasionally drop a connection."""
    last = None
    for _ in range(tries):
        try:
            with urllib.request.urlopen(req_or_url, timeout=timeout) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
        except Exception as e:
            last = e
    sys.exit(f"could not reach endpoint after {tries} tries: {last}")


def discover_manifest(target: str) -> dict:
    """target: a domain (example.com) or a full manifest URL."""
    if target.startswith("http"):
        urls = [target]
    else:
        host = target.split("/")[0]
        urls = [f"https://{host}/.well-known/muse-protocol.json"]
    last = None
    for u in urls:
        try:
            _, body = urlopen_retry(u)
            m = json.loads(body)
            if m.get("protocol") == PROTOCOL:
                m["_manifest_url"] = u
                return m
            last = f"{u}: not a muse-protocol manifest"
        except SystemExit:
            raise
        except Exception as e:
            last = f"{u}: {e}"
    sys.exit(f"manifest discovery failed: {last}")


# --- sealed messages (NaCl) ---

def seal_pwhash(payload: dict, passphrase: str) -> dict:
    """XChaCha20-Poly1305 with an Argon2id key derived from the passphrase."""
    from nacl.pwhash import argon2id
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
    salt = secrets.token_bytes(argon2id.SALTBYTES)
    key = argon2id.kdf(32, passphrase.encode(), salt,
                       opslimit=3, memlimit=64 * 1024 * 1024)
    nonce = secrets.token_bytes(24)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(
        json.dumps(payload, separators=(",", ":")).encode(), None, nonce, key)
    return {"alg": "pwhash-xchacha20poly1305",
            "salt": b64e(salt), "sender_pubkey": None,
            "nonce": b64e(nonce), "ciphertext": b64e(ct)}


def seal_box(payload: dict, recipient_pubkey_b64: str) -> dict:
    """NaCl box to the recipient's manifest x25519_pubkey (ephemeral sender)."""
    from nacl.public import PublicKey, PrivateKey, Box
    eph = PrivateKey.generate()
    box = Box(eph, PublicKey(b64d(recipient_pubkey_b64)))
    nonce = secrets.token_bytes(Box.NONCE_SIZE)
    enc = box.encrypt(json.dumps(payload, separators=(",", ":")).encode(), nonce)
    return {"alg": "box-x25519-xsalsa20poly1305",
            "salt": None, "sender_pubkey": b64e(bytes(eph.public_key)),
            "nonce": b64e(nonce), "ciphertext": b64e(enc.ciphertext)}


def open_sealed(sealed: dict, passphrase: str | None = None,
                secret_key_b64: str | None = None) -> dict:
    alg = sealed.get("alg")
    if alg == "pwhash-xchacha20poly1305":
        if not passphrase:
            raise ValueError("passphrase required to open this message")
        from nacl.pwhash import argon2id
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
        key = argon2id.kdf(32, passphrase.encode(), b64d(sealed["salt"]),
                           opslimit=3, memlimit=64 * 1024 * 1024)
        pt = crypto_aead_xchacha20poly1305_ietf_decrypt(
            b64d(sealed["ciphertext"]), None, b64d(sealed["nonce"]), key)
        return json.loads(pt.decode())
    if alg == "box-x25519-xsalsa20poly1305":
        if not secret_key_b64:
            raise ValueError("recipient secret key required to open this message")
        from nacl.public import PublicKey, PrivateKey, Box
        box = Box(PrivateKey(b64d(secret_key_b64)),
                  PublicKey(b64d(sealed["sender_pubkey"])))
        pt = box.decrypt(b64d(sealed["ciphertext"]), b64d(sealed["nonce"]))
        return json.loads(pt.decode())
    raise ValueError(f"unknown sealed alg: {alg}")


def require_nacl():
    try:
        import nacl.public  # noqa
    except ImportError:
        sys.exit("encryption needs PyNaCl: pip install pynacl")
