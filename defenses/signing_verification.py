"""Defense #4 — package signing verification.

If every legitimate internal artifact is signed by a trusted publisher key and
your installer refuses anything without a valid signature from that key, then an
impostor — which the attacker cannot sign with your key — is rejected. This is
the model behind Sigstore/PEP 740 attestations and signed releases.

Uses ed25519 via `cryptography` when available; otherwise falls back to an
HMAC-based demonstration so the lab works without extra deps. The trust decision
is the same either way: verify against the *trusted* key, reject on failure.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path


def _keydir() -> Path:
    from scsim.config import STATE_DIR
    d = STATE_DIR / "signing"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---- ed25519 path (preferred) ---------------------------------------------
def _try_ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
        from cryptography.hazmat.primitives import serialization
        return Ed25519PrivateKey, Ed25519PublicKey, serialization
    except Exception:
        return None


def generate_keypair() -> dict:
    """Create the trusted publisher keypair (once)."""
    ed = _try_ed25519()
    kd = _keydir()
    if ed:
        Ed25519PrivateKey, _, serialization = ed
        priv = Ed25519PrivateKey.generate()
        (kd / "publisher_ed25519.key").write_bytes(
            priv.private_bytes(serialization.Encoding.Raw,
                               serialization.PrivateFormat.Raw,
                               serialization.NoEncryption()))
        (kd / "publisher_ed25519.pub").write_bytes(
            priv.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw))
        return {"scheme": "ed25519", "pub": str(kd / "publisher_ed25519.pub")}
    # HMAC fallback
    secret = hashlib.sha256(b"scsim-trusted-publisher-demo-key").digest()
    (kd / "hmac.secret").write_bytes(secret)
    return {"scheme": "hmac", "pub": str(kd / "hmac.secret")}


def sign(artifact: Path) -> Path:
    """Sign an artifact with the trusted publisher key -> writes artifact.sig."""
    ed = _try_ed25519()
    kd = _keydir()
    data = Path(artifact).read_bytes()
    sig_path = Path(str(artifact) + ".sig")
    if ed:
        Ed25519PrivateKey, _, serialization = ed
        if not (kd / "publisher_ed25519.key").exists():
            generate_keypair()
        priv = Ed25519PrivateKey.from_private_bytes(
            (kd / "publisher_ed25519.key").read_bytes())
        sig_path.write_bytes(priv.sign(data))
    else:
        if not (kd / "hmac.secret").exists():
            generate_keypair()
        secret = (kd / "hmac.secret").read_bytes()
        sig_path.write_bytes(hmac.new(secret, data, hashlib.sha256).digest())
    return sig_path


def verify(artifact: Path, sig: Path | None = None) -> bool:
    """Verify artifact against the trusted key. Missing/invalid sig -> False."""
    artifact = Path(artifact)
    sig = Path(sig) if sig else Path(str(artifact) + ".sig")
    if not sig.exists():
        return False
    data = artifact.read_bytes()
    signature = sig.read_bytes()
    ed = _try_ed25519()
    kd = _keydir()
    try:
        if ed:
            _, Ed25519PublicKey, serialization = ed
            pub = Ed25519PublicKey.from_public_bytes(
                (kd / "publisher_ed25519.pub").read_bytes())
            pub.verify(signature, data)   # raises on failure
            return True
        secret = (kd / "hmac.secret").read_bytes()
        expected = hmac.new(secret, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False


def test_against_attack() -> dict:
    """The impostor artifact is not signed by the trusted key, so it fails
    verification and is rejected at install time."""
    from scsim.config import DEMO_PKG_DIR
    generate_keypair()
    dist = sorted((DEMO_PKG_DIR / "dist").glob("*.tar.gz"))
    if not dist:
        return {"defense": "signing_verification", "blocked": None,
                "detail": "No built artifact; run publish first."}
    impostor = dist[-1]
    # The attacker cannot produce a valid signature with our key, so there is
    # no trusted .sig for the impostor.
    ok = verify(impostor)
    return {
        "defense": "signing_verification",
        "blocked": not ok,
        "stage_prevented": "install (verification gate)",
        "detail": ("Impostor has no valid signature from the trusted publisher "
                   "key → rejected." if not ok
                   else "Impostor unexpectedly verified."),
    }


if __name__ == "__main__":
    print(json.dumps(test_against_attack(), indent=2))
