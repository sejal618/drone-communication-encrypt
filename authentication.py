# authentication.py - Auth, Digital Signature, HMAC-MAC, Replay Protection

import os, hmac, hashlib, time
from Crypto.PublicKey    import RSA
from Crypto.Signature    import pss
from Crypto.Hash         import SHA256

# ── 3.3  Password-based Authentication ──────────────────────────────────────

def hash_password(password: str) -> tuple[str, str]:
    """Hash a password with a random salt using SHA-256. Returns (salt_hex, hash_hex)."""
    salt   = os.urandom(16)
    digest = hashlib.sha256(salt + password.encode()).hexdigest()
    return salt.hex(), digest

def verify_password(password: str, salt_hex: str, stored_hash: str) -> bool:
    """Verify a login attempt against the stored salt+hash."""
    salt   = bytes.fromhex(salt_hex)
    digest = hashlib.sha256(salt + password.encode()).hexdigest()
    return hmac.compare_digest(digest, stored_hash)   # constant-time compare

# ── 3.4  Digital Signature (RSA-PSS) ────────────────────────────────────────

def generate_signing_keys():
    """Generate RSA-2048 signing key pair for the Drone."""
    key = RSA.generate(2048)
    return key, key.publickey()   # (drone_private, drone_public)

def sign_message(message: bytes, drone_priv_key) -> bytes:
    """Sign a message at the Drone using RSA-PSS + SHA-256."""
    h   = SHA256.new(message)
    sig = pss.new(drone_priv_key).sign(h)
    print("[Signature] Message signed by Drone.")
    return sig

def verify_signature(message: bytes, signature: bytes, drone_pub_key) -> bool:
    """Verify the signature at the Ground Station."""
    try:
        pss.new(drone_pub_key).verify(SHA256.new(message), signature)
        print("[Signature] Signature verified ✓")
        return True
    except (ValueError, TypeError):
        print("[Signature] Signature INVALID ✗")
        return False

# ── 3.5  HMAC-SHA256 Message Integrity ──────────────────────────────────────

def generate_mac(message: bytes, secret_key: bytes) -> bytes:
    """Compute HMAC-SHA256 over the message."""
    mac = hmac.new(secret_key, message, hashlib.sha256).digest()
    print("[MAC] HMAC generated.")
    return mac

def verify_mac(message: bytes, received_mac: bytes, secret_key: bytes) -> bool:
    """Verify HMAC at the receiver."""
    expected = hmac.new(secret_key, message, hashlib.sha256).digest()
    ok = hmac.compare_digest(expected, received_mac)
    print(f"[MAC] Integrity check: {'PASS ✓' if ok else 'FAIL ✗'}")
    return ok

# ── 3.6  Replay Attack Protection (Timestamp) ───────────────────────────────

SEEN_TIMESTAMPS: set = set()   # In real use: persist this or use a sliding window
MAX_AGE_SECONDS = 30           # Reject messages older than 30 s

def attach_timestamp() -> float:
    """Return current UTC timestamp to embed in the message."""
    return time.time()

def check_replay(ts: float) -> bool:
    """
    Return True if the timestamp is fresh and not seen before.
    Rejects: (a) messages older than MAX_AGE_SECONDS, (b) exact duplicate timestamps.
    """
    now = time.time()
    if abs(now - ts) > MAX_AGE_SECONDS:
        print("[Replay] REJECTED – message too old.")
        return False
    if ts in SEEN_TIMESTAMPS:
        print("[Replay] REJECTED – duplicate timestamp (replay detected).")
        return False
    SEEN_TIMESTAMPS.add(ts)
    print("[Replay] Timestamp accepted ✓")
    return True


if __name__ == "__main__":
    # -- Auth test
    salt, hashed = hash_password("drone_secret_123")
    print("[Auth] Login:", verify_password("drone_secret_123", salt, hashed))

    # -- Signature test
    priv, pub = generate_signing_keys()
    msg = b"Test telemetry data"
    sig = sign_message(msg, priv)
    verify_signature(msg, sig, pub)

    # -- MAC test
    key = os.urandom(32)
    mac = generate_mac(msg, key)
    verify_mac(msg, mac, key)

    # -- Replay test
    ts = attach_timestamp()
    check_replay(ts)
    check_replay(ts)   # second call should be rejected
