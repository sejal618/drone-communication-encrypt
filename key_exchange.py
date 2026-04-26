# key_exchange.py - Diffie-Hellman Key Exchange between Drone and Ground Station

from cryptography.hazmat.primitives.asymmetric.dh import generate_parameters
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

def generate_dh_params():
    """Generate shared DH parameters (done once, shared by both parties)."""
    params = generate_parameters(generator=2, key_size=512, backend=default_backend())
    return params

def dh_key_exchange():
    """Simulate DH key exchange. Returns shared_key used as AES key material."""
    params = generate_dh_params()

    # Both sides generate their private keys
    drone_private   = params.generate_private_key()
    station_private = params.generate_private_key()

    # Exchange public keys
    drone_public   = drone_private.public_key()
    station_public = station_private.public_key()

    # Each side computes the shared secret
    drone_shared   = drone_private.exchange(station_public)
    station_shared = station_private.exchange(drone_public)

    # Derive a 32-byte AES key from the shared secret using HKDF
    def derive(shared):
        return HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=None, info=b"drone-session", backend=default_backend()
        ).derive(shared)

    drone_key   = derive(drone_shared)
    station_key = derive(station_shared)

    assert drone_key == station_key, "Key mismatch!"
    print("[Key Exchange] Shared secret established via Diffie-Hellman.")
    return drone_key  # shared symmetric key


if __name__ == "__main__":
    key = dh_key_exchange()
    print(f"[Key Exchange] Derived AES Key (hex): {key.hex()}")
