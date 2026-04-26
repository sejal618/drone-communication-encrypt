# main.py - Secure Drone ↔ Ground Station Communication (Full Demo)
# Integrates: DH Key Exchange, Hybrid Encryption, Auth, Digital Signature, MAC, Replay Protection

import json
from key_exchange   import dh_key_exchange
from encryption     import generate_rsa_keys, hybrid_encrypt, hybrid_decrypt
from authentication import (
    hash_password, verify_password,
    generate_signing_keys, sign_message, verify_signature,
    generate_mac, verify_mac,
    attach_timestamp, check_replay
)

# ═══════════════════════════════════════════════════════════════════
# SETUP  –  keys and credentials (done once before communication)
# ═══════════════════════════════════════════════════════════════════

print("=" * 60)
print("      SECURE DRONE COMMUNICATION SYSTEM")
print("=" * 60)

# 3.1  DH key exchange → shared HMAC/MAC key
print("\n[STEP 1] Diffie-Hellman Key Exchange")
shared_mac_key = dh_key_exchange()

# 3.2  RSA key pair for the Ground Station (for hybrid encryption)
station_rsa_priv, station_rsa_pub = generate_rsa_keys()

# 3.3  Password auth – Drone registers a credential on the station
DRONE_PASSWORD = "drone_secret_123"
salt, stored_hash = hash_password(DRONE_PASSWORD)

# 3.4  RSA signing key pair for the Drone
drone_sign_priv, drone_sign_pub = generate_signing_keys()

# ═══════════════════════════════════════════════════════════════════
# DRONE SIDE  –  prepare and send a secure telemetry message
# ═══════════════════════════════════════════════════════════════════

print("\n[STEP 2] Drone Authentication")
auth_ok = verify_password(DRONE_PASSWORD, salt, stored_hash)
if not auth_ok:
    print("[Auth] FAILED – aborting.")
    exit(1)
print("[Auth] Drone authenticated ✓")

print("\n[STEP 3] Preparing Telemetry Payload")
telemetry = {"drone_id": "DR001", "latitude": 12.97, "longitude": 77.59, "speed": 45}
ts = attach_timestamp()
telemetry["timestamp"] = ts          # embed timestamp for replay protection
print("[Payload]", json.dumps(telemetry, indent=2))

print("\n[STEP 4] Hybrid Encryption")
enc = hybrid_encrypt(telemetry, station_rsa_pub)
# enc keys: enc_aes_key, iv, ciphertext, aes_key

print("\n[STEP 5] Digital Signature (Drone signs the ciphertext)")
signature = sign_message(enc["ciphertext"], drone_sign_priv)

print("\n[STEP 6] Generating HMAC-SHA256 for Integrity")
mac = generate_mac(enc["ciphertext"], shared_mac_key)

# Build the complete packet sent over the wire
packet = {
    "enc_aes_key": enc["enc_aes_key"],
    "iv":          enc["iv"],
    "ciphertext":  enc["ciphertext"],
    "signature":   signature,
    "mac":         mac,
    "timestamp":   ts
}
print("\n[Drone] Packet ready. Transmitting to Ground Station…")

# ═══════════════════════════════════════════════════════════════════
# GROUND STATION SIDE  –  receive and verify
# ═══════════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("      GROUND STATION – RECEIVING PACKET")
print("=" * 60)

print("\n[STEP 7] Replay Attack Check")
if not check_replay(packet["timestamp"]):
    print("[Station] Packet rejected (replay).")
    exit(1)

print("\n[STEP 8] Verifying Digital Signature")
if not verify_signature(packet["ciphertext"], packet["signature"], drone_sign_pub):
    print("[Station] Packet rejected (bad signature).")
    exit(1)

print("\n[STEP 9] Verifying HMAC Integrity")
if not verify_mac(packet["ciphertext"], packet["mac"], shared_mac_key):
    print("[Station] Packet rejected (MAC mismatch).")
    exit(1)

print("\n[STEP 10] Decrypting Payload")
decrypted = hybrid_decrypt(packet["enc_aes_key"], packet["iv"], packet["ciphertext"], station_rsa_priv)
print("\n[Station] Telemetry received successfully:")
print(json.dumps({k: v for k, v in decrypted.items() if k != "timestamp"}, indent=2))

print("\n[BONUS] Replay Attack Simulation")
print("Resending the same packet…")
check_replay(packet["timestamp"])   # should be rejected

print("\n" + "=" * 60)
print("   COMMUNICATION COMPLETE – ALL CHECKS PASSED ✓")
print("=" * 60)
