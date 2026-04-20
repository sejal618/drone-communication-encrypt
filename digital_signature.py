"""
Digital Signature Module - RSA-Based Message Authentication
Author: [Student Name - Customize this]
Date: April 2024
Purpose: Provide authenticity and non-repudiation using RSA digital signatures

WHAT IS A DIGITAL SIGNATURE?
A digital signature is like a mathematical fingerprint that proves:
  1. I am who I say I am (authenticity) - only I have my private key
  2. I really sent this message (non-repudiation) - I can't deny it later
  3. The message hasn't been altered (integrity) - any change breaks signature

HOW IT WORKS:
  Signing (Drone side):
    1. Compute SHA-256 hash of message
    2. Encrypt hash with my private key (only I have this!)
    3. Send: message + signature
    
  Verifying (Ground Station side):
    1. Decrypt signature with drone's public key
    2. Compute SHA-256 hash of received message
    3. Compare: if hashes match, signature is valid

WHY RSA?
  - Security: Only private key holder can create valid signatures
  - Public key can verify without needing private key
  - Well-established and widely trusted

ATTACKS IT PREVENTS:
  ✓ Forgery: Attacker can't create valid signature without private key
  ✓ Tampering: Any message change makes signature invalid
  ✓ Repudiation: Signer can't claim "I didn't send this"
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64


class DigitalSignature:
    """
    Digital Signature System using RSA and SHA-256
    
    Ensures:
    - Authenticity: Only holder of private key can sign
    - Non-repudiation: Signer cannot deny signing the message
    - Integrity: Any change in message invalidates signature
    
    Workflow:
    1. Signer hashes message with SHA-256
    2. Signer encrypts hash with RSA private key
    3. Receiver verifies with signer's RSA public key
    """
    
    def __init__(self):
        """Initialize with RSA key pair"""
        self.rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.rsa_key.public_key()
    
    def get_public_key(self) -> str:
        """
        Export public key in PEM format (base64-encoded)
        
        Returns:
            str: Base64-encoded RSA public key
        """
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_pem).decode('utf-8')
    
    def sign_message(self, message: str) -> str:
        """
        Sign a message using RSA private key
        
        Args:
            message: Message to sign (string)
            
        Returns:
            str: Base64-encoded signature
        """
        message_bytes = message.encode('utf-8') if isinstance(message, str) else message
        
        # Sign with private key using PSS padding
        signature = self.rsa_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, message: str, signature_b64: str, public_key_b64: str) -> bool:
        """
        Verify a message signature using public key
        
        Args:
            message: Original message
            signature_b64: Base64-encoded signature
            public_key_b64: Base64-encoded public key of signer
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            message_bytes = message.encode('utf-8') if isinstance(message, str) else message
            
            # Decode public key
            public_pem = base64.b64decode(public_key_b64)
            public_key = serialization.load_pem_public_key(
                public_pem,
                backend=default_backend()
            )
            
            # Decode signature
            signature = base64.b64decode(signature_b64)
            
            # Verify signature
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        
        except Exception as e:
            return False


class MessageSignatureManager:
    """
    Manages signing and verification of messages in the drone system
    """
    
    def __init__(self, entity_name: str = "Entity"):
        self.entity_name = entity_name
        self.signature_handler = DigitalSignature()
    
    def get_public_key(self) -> str:
        """Get this entity's public key"""
        return self.signature_handler.get_public_key()
    
    def sign_message(self, message: str) -> str:
        """
        Sign a message
        
        Args:
            message: Message to sign
            
        Returns:
            str: Signature
        """
        return self.signature_handler.sign_message(message)
    
    @staticmethod
    def verify_message(message: str, signature: str, public_key: str) -> bool:
        """
        Verify a signed message
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Signer's public key
            
        Returns:
            bool: True if valid, False otherwise
        """
        verifier = DigitalSignature()
        return verifier.verify_signature(message, signature, public_key)


if __name__ == "__main__":
    # Demonstrate Digital Signature
    print("=" * 70)
    print("DIGITAL SIGNATURE (RSA + SHA-256) DEMONSTRATION")
    print("=" * 70)
    
    # Create drone signature manager
    drone_sig = MessageSignatureManager("Drone")
    public_key = drone_sig.get_public_key()
    
    # Message to sign
    message = '{"drone_id": "DR001", "latitude": 12.97, "longitude": 77.59, "speed": 45}'
    
    print(f"\nOriginal Message:\n{message}")
    
    # Sign the message
    signature = drone_sig.sign_message(message)
    print(f"\nSignature (first 32 chars): {signature[:32]}...")
    print(f"Signature length: {len(signature)} characters")
    
    # Verify signature
    print(f"\n[Verification 1] Verifying with correct message...")
    is_valid = MessageSignatureManager.verify_message(message, signature, public_key)
    print(f"Result: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    # Try with tampered message
    tampered_message = '{"drone_id": "DR001", "latitude": 12.97, "longitude": 77.59, "speed": 90}'
    print(f"\n[Verification 2] Verifying with tampered message...")
    print(f"Tampered Message:\n{tampered_message}")
    is_valid_tampered = MessageSignatureManager.verify_message(tampered_message, signature, public_key)
    print(f"Result: {'✓ VALID' if is_valid_tampered else '✗ INVALID'}")
    
    if not is_valid_tampered:
        print("\n✓ Message integrity protection working! Tampered message detected.")
    
    print("=" * 70)
