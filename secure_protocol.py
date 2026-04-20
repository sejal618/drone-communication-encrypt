"""
Secure Protocol Module
Integrates all cryptographic components into a complete secure communication protocol
"""

import json
import base64
from typing import Dict, Optional

from key_exchange import DiffieHellmanKeyExchange, perform_key_exchange
from encryption import HybridEncryption, hybrid_encrypt_workflow, hybrid_decrypt_workflow
from authentication import AuthenticationSession
from digital_signature import MessageSignatureManager
from integrity import IntegrityManager
from replay_protection import ReplayProtectionManager


class SecureMessage:
    """
    Represents a secure message with all security components
    """
    
    def __init__(self):
        self.timestamp = None
        self.nonce = None
        self.encrypted_data = None
        self.signature = None
        self.hmac = None
        self.drone_id = None
        self.encrypted_aes_key = None
        self.iv = None
    
    def to_json(self) -> str:
        """Serialize message to JSON"""
        return json.dumps({
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'drone_id': self.drone_id,
            'encrypted_aes_key': self.encrypted_aes_key,
            'encrypted_data': self.encrypted_data,
            'iv': self.iv,
            'signature': self.signature,
            'hmac': self.hmac
        })
    
    @staticmethod
    def from_json(json_str: str) -> 'SecureMessage':
        """Deserialize message from JSON"""
        data = json.loads(json_str)
        msg = SecureMessage()
        msg.timestamp = data.get('timestamp')
        msg.nonce = data.get('nonce')
        msg.drone_id = data.get('drone_id')
        msg.encrypted_aes_key = data.get('encrypted_aes_key')
        msg.encrypted_data = data.get('encrypted_data')
        msg.iv = data.get('iv')
        msg.signature = data.get('signature')
        msg.hmac = data.get('hmac')
        return msg


class DroneProtocol:
    """
    Secure communication protocol for Drone
    Handles encryption, signing, MAC, and replay protection
    """
    
    def __init__(self, drone_id: str, password: str):
        self.drone_id = drone_id
        self.password = password
        
        # Initialize components
        self.signature_mgr = MessageSignatureManager(f"Drone-{drone_id}")
        self.replay_mgr = ReplayProtectionManager()
        self.encryption = HybridEncryption()
        
        # Will be set after key exchange and authentication
        self.gcs_public_key = None
        self.shared_secret = None
        self.integrity_mgr = None
        self.authenticated = False
        self.auth_token = None
    
    def get_public_key(self) -> str:
        """Get drone's RSA public key"""
        return self.encryption.get_public_key()
    
    def get_signature_public_key(self) -> str:
        """Get drone's signature public key"""
        return self.signature_mgr.get_public_key()
    
    def set_shared_secret(self, shared_secret: int):
        """
        Set the shared secret from DH key exchange
        
        Args:
            shared_secret: Integer from DH exchange
        """
        # Convert shared secret to string for HMAC operations
        self.shared_secret = str(shared_secret)
        self.integrity_mgr = IntegrityManager(self.shared_secret)
    
    def create_secure_message(self, telemetry_data: Dict) -> SecureMessage:
        """
        Create a secure message with all security components
        
        Workflow:
        1. Add timestamp and nonce (replay protection)
        2. Encrypt data with AES (hybrid encryption)
        3. Sign encrypted data (authenticity)
        4. Compute HMAC (integrity)
        
        Args:
            telemetry_data: Data to send (dict)
            
        Returns:
            SecureMessage: Complete secure message
        """
        if not self.authenticated:
            raise ValueError("Drone not authenticated")
        
        if self.gcs_public_key is None:
            raise ValueError("GCS public key not set")
        
        # Step 1: Generate replay protection tokens
        protection_tokens = self.replay_mgr.generate_protection_tokens()
        timestamp = protection_tokens['timestamp']
        nonce = protection_tokens['nonce']
        
        # Step 2: Encrypt telemetry data with GCS public key
        encrypted_pkg = hybrid_encrypt_workflow(telemetry_data, self.gcs_public_key)
        
        # Step 3: Create message to sign (include encrypted data + metadata)
        message_to_sign = json.dumps({
            'drone_id': self.drone_id,
            'timestamp': timestamp,
            'nonce': nonce,
            'encrypted_data': encrypted_pkg['encrypted_data']
        })
        
        # Step 4: Sign the message
        signature = self.signature_mgr.sign_message(message_to_sign)
        
        # Step 5: Compute HMAC of entire message for integrity
        hmac = self.integrity_mgr.compute_mac(message_to_sign)
        
        # Step 6: Assemble secure message
        secure_msg = SecureMessage()
        secure_msg.timestamp = timestamp
        secure_msg.nonce = nonce
        secure_msg.drone_id = self.drone_id
        secure_msg.encrypted_aes_key = encrypted_pkg['encrypted_aes_key']
        secure_msg.encrypted_data = encrypted_pkg['encrypted_data']
        secure_msg.iv = encrypted_pkg['iv']
        secure_msg.signature = signature
        secure_msg.hmac = hmac
        
        return secure_msg
    
    def set_gcs_public_key(self, gcs_public_key: str):
        """Set the GCS's RSA public key for encryption"""
        self.gcs_public_key = gcs_public_key


class GroundStationProtocol:
    """
    Secure communication protocol for Ground Control Station
    Handles decryption, signature verification, MAC validation, and replay protection
    """
    
    def __init__(self):
        # Initialize components
        self.signature_mgr = MessageSignatureManager("GroundStation")
        self.replay_mgr = ReplayProtectionManager()
        self.encryption = HybridEncryption()
        self.auth_session = AuthenticationSession()
        
        # Will be set after key exchange
        self.shared_secret = None
        self.integrity_mgr = None
        
        # Store drone public keys for signature verification
        self.drone_public_keys = {}  # {drone_id: public_key}
        self.drone_signature_keys = {}  # {drone_id: signature_public_key}
    
    def get_public_key(self) -> str:
        """Get GCS's RSA public key"""
        return self.encryption.get_public_key()
    
    def register_drone(self, drone_id: str, password: str) -> Dict:
        """Register a new drone"""
        return self.auth_session.register_drone(drone_id, password)
    
    def initiate_authentication(self, drone_id: str) -> Dict:
        """Initiate challenge-response authentication"""
        return self.auth_session.initiate_authentication(drone_id)
    
    def authenticate_drone(self, drone_id: str, challenge_response: str) -> Dict:
        """Authenticate drone based on challenge response"""
        return self.auth_session.authenticate_drone(drone_id, challenge_response)
    
    def set_shared_secret(self, shared_secret: int):
        """Set shared secret from DH key exchange"""
        self.shared_secret = str(shared_secret)
        self.integrity_mgr = IntegrityManager(self.shared_secret)
    
    def register_drone_keys(self, drone_id: str, drone_public_key: str, 
                           drone_signature_key: str):
        """Register drone's public keys for future verification"""
        self.drone_public_keys[drone_id] = drone_public_key
        self.drone_signature_keys[drone_id] = drone_signature_key
    
    def receive_secure_message(self, secure_msg: SecureMessage) -> Optional[Dict]:
        """
        Receive and verify a secure message
        
        Verification steps:
        1. Check replay protection (timestamp + nonce)
        2. Verify HMAC (integrity)
        3. Verify signature (authenticity)
        4. Decrypt data (confidentiality)
        
        Args:
            secure_msg: Received secure message
            
        Returns:
            dict: Decrypted telemetry data, or None if verification failed
        """
        drone_id = secure_msg.drone_id
        
        # Step 1: Replay Protection
        replay_check = self.replay_mgr.check_message(
            secure_msg.timestamp,
            secure_msg.nonce
        )
        
        if not replay_check['valid']:
            print(f"✗ Replay protection check failed: {replay_check['reason']}")
            return None
        
        # Step 2: Verify HMAC (Integrity)
        message_to_verify = json.dumps({
            'drone_id': drone_id,
            'timestamp': secure_msg.timestamp,
            'nonce': secure_msg.nonce,
            'encrypted_data': secure_msg.encrypted_data
        })
        
        if not self.integrity_mgr.verify_mac(message_to_verify, secure_msg.hmac):
            print("✗ HMAC verification failed (message integrity compromised)")
            return None
        
        # Step 3: Verify Digital Signature (Authenticity)
        if drone_id not in self.drone_signature_keys:
            print(f"✗ Unknown drone: {drone_id}")
            return None
        
        drone_sig_key = self.drone_signature_keys[drone_id]
        if not MessageSignatureManager.verify_message(
            message_to_verify,
            secure_msg.signature,
            drone_sig_key
        ):
            print("✗ Digital signature verification failed (authenticity compromised)")
            return None
        
        # Step 4: Decrypt Message (Confidentiality)
        try:
            encrypted_pkg = {
                'encrypted_aes_key': secure_msg.encrypted_aes_key,
                'encrypted_data': secure_msg.encrypted_data,
                'iv': secure_msg.iv
            }
            
            decrypted_data = hybrid_decrypt_workflow(encrypted_pkg, self.encryption)
            return decrypted_data
        
        except Exception as e:
            print(f"✗ Decryption failed: {e}")
            return None


if __name__ == "__main__":
    print("Secure Protocol module loaded successfully!")
    print("This module integrates all cryptographic components.")
