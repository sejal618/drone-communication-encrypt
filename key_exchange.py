"""
Diffie-Hellman Key Exchange Implementation
Author: [Student Name - Customize this]
Date: April 2024
Purpose: Secure key exchange protocol for drone-to-ground communication

This module implements the Diffie-Hellman key exchange algorithm, allowing two parties
(Drone and Ground Station) to establish a shared secret key without ever transmitting
the secret itself. The security is based on the discrete logarithm problem - it's easy
to compute g^x mod p, but hard to reverse (find x given g^x mod p).

Key Concept: Both parties end up with the same shared secret despite an attacker
potentially intercepting all communications.
"""

import random
from typing import Tuple


class DiffieHellmanKeyExchange:
    """
    Implements Diffie-Hellman Key Exchange Protocol
    
    Standard DH parameters (MODP group 1024-bit):
    - p: Large prime number
    - g: Generator
    
    Security: 1024-bit DH is suitable for demonstration purposes.
    Production systems should use 2048-bit or higher.
    """
    
    # Standard MODP Group parameters (RFC 2409 - 1024-bit)
    # For production, use higher bit lengths
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
    G = 2
    
    def __init__(self, name: str = "DH_Party"):
        """
        Initialize DH instance
        
        Args:
            name: Name of the party (e.g., "Drone", "GroundStation")
        """
        self.name = name
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        
    def generate_private_key(self) -> int:
        """
        Generate a random private key
        2 <= private_key < P-1
        
        Returns:
            int: Generated private key
        """
        self.private_key = random.randint(2, self.P - 2)
        return self.private_key
    
    def generate_public_key(self, private_key: int = None) -> int:
        """
        Calculate public key: g^private_key mod p
        
        Args:
            private_key: If provided, use this; otherwise use stored private_key
            
        Returns:
            int: Calculated public key
        """
        if private_key is None:
            if self.private_key is None:
                raise ValueError("Private key not initialized. Call generate_private_key() first.")
            private_key = self.private_key
        
        self.public_key = pow(self.G, private_key, self.P)
        return self.public_key
    
    def compute_shared_secret(self, other_public_key: int, private_key: int = None) -> int:
        """
        Compute shared secret: other_public_key^private_key mod p
        
        Args:
            other_public_key: The public key received from the other party
            private_key: If provided, use this; otherwise use stored private_key
            
        Returns:
            int: Computed shared secret
        """
        if private_key is None:
            if self.private_key is None:
                raise ValueError("Private key not initialized.")
            private_key = self.private_key
        
        self.shared_secret = pow(other_public_key, private_key, self.P)
        return self.shared_secret
    
    def get_parameters(self) -> Tuple[int, int]:
        """Return DH parameters (p, g)"""
        return (self.P, self.G)


def perform_key_exchange() -> Tuple[int, int, int]:
    """
    Simulate complete DH key exchange between two parties
    
    Returns:
        Tuple: (drone_public_key, ground_station_public_key, shared_secret)
    """
    # Initialize both parties
    drone = DiffieHellmanKeyExchange("Drone")
    gcs = DiffieHellmanKeyExchange("GroundStation")
    
    # Step 1: Each party generates private key
    drone_private = drone.generate_private_key()
    gcs_private = gcs.generate_private_key()
    
    # Step 2: Each party calculates public key
    drone_public = drone.generate_public_key(drone_private)
    gcs_public = gcs.generate_public_key(gcs_private)
    
    # Step 3: Exchange public keys and compute shared secret
    drone_shared = drone.compute_shared_secret(gcs_public, drone_private)
    gcs_shared = gcs.compute_shared_secret(drone_public, gcs_private)
    
    # Verify they have the same shared secret
    assert drone_shared == gcs_shared, "Shared secrets don't match!"
    
    return drone_public, gcs_public, drone_shared


if __name__ == "__main__":
    # Demonstrate DH Key Exchange
    print("=" * 70)
    print("DIFFIE-HELLMAN KEY EXCHANGE DEMONSTRATION")
    print("=" * 70)
    
    drone_pub, gcs_pub, shared = perform_key_exchange()
    
    print(f"\nDrone Public Key (last 16 digits): ...{str(drone_pub)[-16:]}")
    print(f"GCS Public Key (last 16 digits):   ...{str(gcs_pub)[-16:]}")
    print(f"\nShared Secret (last 32 digits): ...{str(shared)[-32:]}")
    print("\n✓ Key Exchange Successful! Both parties derived the same shared secret.")
    print("=" * 70)
