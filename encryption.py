# encryption.py - Hybrid Encryption: RSA wraps AES session key; AES-CBC encrypts data

import os, json
from Crypto.PublicKey  import RSA
from Crypto.Cipher     import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

# ── RSA key generation ──────────────────────────────────────────────────────

def generate_rsa_keys():
    """Generate RSA-2048 key pair for the Ground Station."""
    key = RSA.generate(2048)
    return key, key.publickey()   # (private, public)

# ── AES-CBC helpers ─────────────────────────────────────────────────────────

def aes_encrypt(data: bytes, aes_key: bytes) -> tuple[bytes, bytes]:
    """Encrypt bytes with AES-256-CBC. Returns (iv, ciphertext)."""
    iv     = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(data, AES.block_size))

def aes_decrypt(iv: bytes, ciphertext: bytes, aes_key: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext."""
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# ── Hybrid scheme ────────────────────────────────────────────────────────────

def hybrid_encrypt(payload: dict, station_pub_key) -> dict:
    """
    Drone side:
      1. Generate a fresh AES-256 session key
      2. Encrypt the session key with the station's RSA public key
      3. Encrypt the payload with AES-CBC
    """
    aes_key        = os.urandom(32)                        # random 256-bit session key
    rsa_cipher     = PKCS1_OAEP.new(station_pub_key)
    enc_aes_key    = rsa_cipher.encrypt(aes_key)           # RSA-wrapped AES key
    iv, ciphertext = aes_encrypt(json.dumps(payload).encode(), aes_key)

    print("[Encryption] Payload encrypted with AES-256-CBC.")
    return {
        "enc_aes_key": enc_aes_key,   # bytes
        "iv":          iv,            # bytes
        "ciphertext":  ciphertext,    # bytes
        "aes_key":     aes_key        # kept for MAC generation in main.py
    }

def hybrid_decrypt(enc_aes_key: bytes, iv: bytes, ciphertext: bytes, station_priv_key) -> dict:
    """
    Station side:
      1. Decrypt AES key with RSA private key
      2. Decrypt payload with recovered AES key
    """
    rsa_cipher = PKCS1_OAEP.new(station_priv_key)
    aes_key    = rsa_cipher.decrypt(enc_aes_key)
    plaintext  = aes_decrypt(iv, ciphertext, aes_key)

    print("[Decryption] Payload decrypted successfully.")
    return json.loads(plaintext)


if __name__ == "__main__":
    priv, pub = generate_rsa_keys()
    payload   = {"drone_id": "DR001", "latitude": 12.97, "longitude": 77.59, "speed": 45}

    enc = hybrid_encrypt(payload, pub)
    dec = hybrid_decrypt(enc["enc_aes_key"], enc["iv"], enc["ciphertext"], priv)
    print("[Encryption Test] Decrypted payload:", dec)
