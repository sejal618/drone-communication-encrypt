"""
Message Integrity Module - HMAC Authentication Code
Author: [Student Name - Customize this]
Date: April 2024
Purpose: Detect message tampering and verify sender identity

WHY HMAC INSTEAD OF PLAIN HASH?
Bad approach: MAC = SHA256(message)
  Problem: Attacker can modify message + compute new hash = we don't detect it!
  
Good approach: MAC = HMAC(key, message) where key is secret
  Benefit: Attacker doesn't know the key, can't forge valid HMAC
  Result: Any modification is detected

DIFFERENCE: Signature vs HMAC
  Digital Signature (RSA):
    - Only sender can create (private key secret)
    - Anyone can verify (public key public)
    - Non-repudiation: signer can't deny it
    - Asymmetric (different keys for sign/verify)
    
  HMAC:
    - Both parties share the same key
    - Both can create AND verify
    - No non-repudiation (both could have created it)
    - Symmetric (same key for both)

In our system:
  - We use RSA signature for authenticity (who sent it)
  - We use HMAC for integrity (was it modified)
  - We use Timestamp for replay protection (when was it sent)
  - Together they provide complete message security
"""

import hmac
import hashlib
import base64


class MessageIntegrity:
    """
    Message Authentication Code (MAC) using HMAC-SHA256
    
    Purpose:
    - Verify message hasn't been altered
    - Verify message came from expected sender
    - Unlike signatures, both parties share the HMAC key
    
    Workflow:
    1. Sender computes: HMAC-SHA256(message, shared_secret_key)
    2. Sender transmits: message + HMAC
    3. Receiver recomputes HMAC and compares
    """
    
    @staticmethod
    def compute_hmac(message: str, secret_key: str) -> str:
        """
        Compute HMAC-SHA256 of a message
        
        Args:
            message: Message string
            secret_key: Shared secret key (can be derived from shared secret)
            
        Returns:
            str: Base64-encoded HMAC
        """
        # Convert to bytes if necessary
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message
        
        if isinstance(secret_key, str):
            key_bytes = secret_key.encode('utf-8')
        else:
            key_bytes = secret_key
        
        # Compute HMAC-SHA256
        hmac_obj = hmac.new(key_bytes, message_bytes, hashlib.sha256)
        hmac_digest = hmac_obj.digest()
        
        # Return base64-encoded
        return base64.b64encode(hmac_digest).decode('utf-8')
    
    @staticmethod
    def verify_hmac(message: str, expected_hmac: str, secret_key: str) -> bool:
        """
        Verify HMAC of a message
        
        Args:
            message: Original message
            expected_hmac: Expected HMAC (base64-encoded)
            secret_key: Shared secret key
            
        Returns:
            bool: True if HMAC matches, False otherwise
        """
        # Compute HMAC
        computed_hmac = MessageIntegrity.compute_hmac(message, secret_key)
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(computed_hmac, expected_hmac)


class IntegrityManager:
    """
    Manages message integrity verification in the drone system
    """
    
    def __init__(self, shared_secret: str):
        """
        Initialize with a shared secret key
        
        Args:
            shared_secret: Key derived from DH key exchange or other method
        """
        self.shared_secret = shared_secret
    
    def compute_mac(self, message: str) -> str:
        """
        Compute MAC for a message
        
        Args:
            message: Message to compute MAC for
            
        Returns:
            str: Base64-encoded HMAC-SHA256
        """
        return MessageIntegrity.compute_hmac(message, self.shared_secret)
    
    def verify_mac(self, message: str, mac: str) -> bool:
        """
        Verify MAC of a message
        
        Args:
            message: Original message
            mac: MAC to verify
            
        Returns:
            bool: True if MAC is valid, False otherwise
        """
        return MessageIntegrity.verify_hmac(message, mac, self.shared_secret)


if __name__ == "__main__":
    # Demonstrate HMAC-SHA256
    print("=" * 70)
    print("MESSAGE INTEGRITY (HMAC-SHA256) DEMONSTRATION")
    print("=" * 70)
    
    # Simulate shared secret from DH key exchange
    shared_secret = "shared_secret_key_12345678901234"
    
    # Create integrity manager
    integrity_mgr = IntegrityManager(shared_secret)
    
    # Message to protect
    message = '{"drone_id": "DR001", "latitude": 12.97, "longitude": 77.59, "speed": 45}'
    
    print(f"\nOriginal Message:\n{message}")
    
    # Compute MAC
    mac = integrity_mgr.compute_mac(message)
    print(f"\nComputed HMAC-SHA256: {mac}")
    
    # Verify with correct message
    print(f"\n[Verification 1] Verifying with correct message...")
    is_valid = integrity_mgr.verify_mac(message, mac)
    print(f"Result: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    # Try with tampered message
    tampered_message = '{"drone_id": "DR001", "latitude": 12.97, "longitude": 77.59, "speed": 90}'
    print(f"\n[Verification 2] Verifying with tampered message...")
    is_valid_tampered = integrity_mgr.verify_mac(tampered_message, mac)
    print(f"Result: {'✓ VALID' if is_valid_tampered else '✗ INVALID'}")
    
    if not is_valid_tampered:
        print("\n✓ Integrity protection working! Message tampering detected.")
    
    # Try with wrong MAC
    print(f"\n[Verification 3] Verifying with wrong MAC...")
    wrong_mac = "dGVzdA=="  # Random base64
    is_valid_wrong = integrity_mgr.verify_mac(message, wrong_mac)
    print(f"Result: {'✓ VALID' if is_valid_wrong else '✗ INVALID'}")
    
    print("=" * 70)
