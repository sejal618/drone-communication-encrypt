"""
Hybrid Encryption Module (RSA + AES)
Author: [Student Name - Customize this]
Date: April 2024
Purpose: Secure data encryption combining asymmetric (RSA) and symmetric (AES) cryptography

KEY LEARNING:
Why use hybrid encryption?
  - RSA is secure but slow (good for small keys, bad for bulk data)
  - AES is fast but needs pre-shared key (symmetric problem)
  - Solution: Use RSA to securely transmit AES key, then use AES for data
  - This gives us the best of both worlds: security AND performance

Real-world use: This is how PGP, TLS, and most enterprise systems work!
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import json


class HybridEncryption:
    """
    Hybrid Encryption System using RSA for key exchange and AES for data encryption.
    
    Workflow:
    1. Generate RSA key pair (2048-bit)
    2. Generate random AES session key (32 bytes = 256-bit)
    3. Encrypt AES key with RSA public key
    4. Encrypt data with AES key
    
    This approach combines RSA's key exchange capability with AES's efficiency.
    """
    
    def __init__(self):
        """Initialize RSA key pair"""
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
        self.aes_key = None
        self.iv = None
    
    def get_public_key(self) -> str:
        """
        Export public key in PEM format
        
        Returns:
            str: Base64-encoded RSA public key
        """
        return base64.b64encode(self.public_key.export_key()).decode('utf-8')
    
    def generate_aes_key(self) -> bytes:
        """
        Generate a random AES-256 session key (32 bytes)
        
        Returns:
            bytes: Random AES key
        """
        self.aes_key = get_random_bytes(32)  # 256-bit key
        return self.aes_key
    
    def encrypt_aes_key_with_rsa(self, aes_key: bytes, rsa_public_key_str: str) -> str:
        """
        Encrypt AES key using RSA public key (PKCS1_OAEP padding)
        
        Args:
            aes_key: The AES key to encrypt
            rsa_public_key_str: Base64-encoded RSA public key
            
        Returns:
            str: Base64-encoded encrypted AES key
        """
        from Crypto.Cipher import PKCS1_OAEP
        
        public_key_bytes = base64.b64decode(rsa_public_key_str)
        public_key = RSA.import_key(public_key_bytes)
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_key = cipher.encrypt(aes_key)
        
        return base64.b64encode(encrypted_key).decode('utf-8')
    
    def decrypt_aes_key_with_rsa(self, encrypted_key_str: str) -> bytes:
        """
        Decrypt AES key using RSA private key
        
        Args:
            encrypted_key_str: Base64-encoded encrypted AES key
            
        Returns:
            bytes: Decrypted AES key
        """
        from Crypto.Cipher import PKCS1_OAEP
        
        encrypted_key = base64.b64decode(encrypted_key_str)
        cipher = PKCS1_OAEP.new(self.rsa_key)
        aes_key = cipher.decrypt(encrypted_key)
        
        return aes_key
    
    def encrypt_aes_cbc(self, data: str, aes_key: bytes) -> dict:
        """
        Encrypt data using AES-256-CBC mode
        
        Args:
            data: Plaintext data (string)
            aes_key: AES encryption key (32 bytes)
            
        Returns:
            dict: {
                'ciphertext': Base64-encoded ciphertext,
                'iv': Base64-encoded IV
            }
        """
        # Generate random IV (16 bytes for AES)
        iv = get_random_bytes(16)
        self.iv = iv
        
        # Create AES cipher in CBC mode
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        
        # Convert string to bytes and pad to multiple of 16
        plaintext = data.encode('utf-8') if isinstance(data, str) else data
        padded_plaintext = pad(plaintext, AES.block_size)
        
        # Encrypt
        ciphertext = cipher.encrypt(padded_plaintext)
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }
    
    def decrypt_aes_cbc(self, ciphertext_b64: str, iv_b64: str, aes_key: bytes) -> str:
        """
        Decrypt data using AES-256-CBC mode
        
        Args:
            ciphertext_b64: Base64-encoded ciphertext
            iv_b64: Base64-encoded IV
            aes_key: AES decryption key (32 bytes)
            
        Returns:
            str: Decrypted plaintext
        """
        # Decode from base64
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        
        # Create AES cipher in CBC mode
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        
        # Decrypt and unpad
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size)
        
        return plaintext.decode('utf-8')


def hybrid_encrypt_workflow(data: dict, recipient_public_key: str) -> dict:
    """
    Complete hybrid encryption workflow:
    1. Generate AES key
    2. Encrypt AES key with RSA public key
    3. Encrypt data with AES
    
    Args:
        data: Data to encrypt (will be JSON-serialized)
        recipient_public_key: Recipient's RSA public key (base64)
        
    Returns:
        dict: {
            'encrypted_aes_key': Encrypted AES key,
            'encrypted_data': Encrypted data,
            'iv': IV for AES decryption
        }
    """
    # Initialize encryption system with recipient's public key
    encryptor = HybridEncryption()
    
    # Step 1: Generate AES key
    aes_key = encryptor.generate_aes_key()
    
    # Step 2: Encrypt AES key with recipient's RSA public key
    encrypted_aes_key = encryptor.encrypt_aes_key_with_rsa(aes_key, recipient_public_key)
    
    # Step 3: Encrypt data with AES
    data_json = json.dumps(data)
    encryption_result = encryptor.encrypt_aes_cbc(data_json, aes_key)
    
    return {
        'encrypted_aes_key': encrypted_aes_key,
        'encrypted_data': encryption_result['ciphertext'],
        'iv': encryption_result['iv']
    }


def hybrid_decrypt_workflow(encrypted_package: dict, decryptor: HybridEncryption) -> dict:
    """
    Complete hybrid decryption workflow:
    1. Decrypt AES key with RSA private key
    2. Decrypt data with AES key
    
    Args:
        encrypted_package: Package with encrypted_aes_key, encrypted_data, iv
        decryptor: HybridEncryption instance with RSA private key
        
    Returns:
        dict: Decrypted data
    """
    # Step 1: Decrypt AES key
    aes_key = decryptor.decrypt_aes_key_with_rsa(encrypted_package['encrypted_aes_key'])
    
    # Step 2: Decrypt data
    plaintext = decryptor.decrypt_aes_cbc(
        encrypted_package['encrypted_data'],
        encrypted_package['iv'],
        aes_key
    )
    
    return json.loads(plaintext)


if __name__ == "__main__":
    # Demonstrate Hybrid Encryption
    print("=" * 70)
    print("HYBRID ENCRYPTION (RSA + AES) DEMONSTRATION")
    print("=" * 70)
    
    # Create encryption system and get public key
    encryptor = HybridEncryption()
    public_key = encryptor.get_public_key()
    
    # Sample telemetry data
    telemetry = {
        "drone_id": "DR001",
        "latitude": 12.97,
        "longitude": 77.59,
        "speed": 45,
        "altitude": 1500
    }
    
    print(f"\nOriginal Data: {telemetry}")
    
    # Encrypt
    encrypted_package = hybrid_encrypt_workflow(telemetry, public_key)
    print(f"\nEncrypted AES Key (first 32 chars): {encrypted_package['encrypted_aes_key'][:32]}...")
    print(f"Encrypted Data (first 32 chars): {encrypted_package['encrypted_data'][:32]}...")
    
    # Decrypt
    decrypted_data = hybrid_decrypt_workflow(encrypted_package, encryptor)
    print(f"\nDecrypted Data: {decrypted_data}")
    
    # Verify
    if decrypted_data == telemetry:
        print("\n✓ Encryption/Decryption Successful!")
    else:
        print("\n✗ Decryption failed!")
    
    print("=" * 70)
