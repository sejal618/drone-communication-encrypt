"""
Authentication Module - Challenge-Response Pattern
Author: [Student Name - Customize this]
Date: April 2024
Purpose: Secure authentication without transmitting passwords

AUTHENTICATION PHILOSOPHY:
The fundamental rule: NEVER transmit passwords in plaintext, even over encrypted channels!

How Challenge-Response works:
  Server & Client both know: password_hash = SHA256(password + salt)
  
  Each login:
    1. Server sends: challenge (random nonce)
    2. Client sends: hash(password_hash + challenge)
    3. Server verifies this matches: hash(its_password_hash + challenge)
  
  Why it's secure:
    - Password never transmitted
    - Attacker cannot reuse a previous response (different challenge each time)
    - Forces attacker to break the hash function

This prevents:
  ✓ Passive eavesdropping (no password sent)
  ✓ Replay attacks (new challenge each time)
  ✓ Man-in-the-middle (attacker can't extract password from response)
"""

import hashlib
import secrets
import json
from typing import Tuple


class PasswordAuthenticator:
    """
    Challenge-Response Authentication System
    
    Workflow:
    1. Register: Hash password with random salt -> store hash
    2. Authenticate: Server sends challenge -> Client hashes (password + challenge) -> 
       Server verifies response
    
    Security: Passwords never transmitted in plaintext. Uses SHA-256 with salt.
    """
    
    def __init__(self):
        """Initialize authenticator with user database"""
        # In production, this would be a database
        # Format: {username: {'password_hash': hash, 'salt': salt}}
        self.user_db = {}
    
    @staticmethod
    def generate_salt(length: int = 32) -> str:
        """
        Generate a random salt
        
        Args:
            length: Length in bytes
            
        Returns:
            str: Hex-encoded random salt
        """
        return secrets.token_hex(length)
    
    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """
        Hash password with salt using SHA-256
        
        Args:
            password: Plaintext password
            salt: Salt value
            
        Returns:
            str: Hash digest (hex)
        """
        combined = password + salt
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()
    
    def register_user(self, username: str, password: str) -> dict:
        """
        Register a new user (store hashed password with salt)
        
        Args:
            username: Username
            password: Plaintext password
            
        Returns:
            dict: Registration result {'status': 'success'/'error', 'message': '...'}
        """
        if username in self.user_db:
            return {'status': 'error', 'message': 'User already exists'}
        
        salt = self.generate_salt()
        password_hash = self.hash_password(password, salt)
        
        self.user_db[username] = {
            'password_hash': password_hash,
            'salt': salt
        }
        
        return {'status': 'success', 'message': f'User {username} registered'}
    
    def generate_challenge(self) -> str:
        """
        Generate a random challenge for authentication
        
        Returns:
            str: Random challenge (64 hex characters)
        """
        return secrets.token_hex(32)
    
    def verify_challenge_response(self, username: str, challenge: str, response: str) -> bool:
        """
        Verify the challenge response
        
        Client should: response = hash(password + challenge)
        
        Args:
            username: Username
            challenge: Challenge sent to client
            response: Response from client
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        if username not in self.user_db:
            return False
        
        user_record = self.user_db[username]
        
        # For challenge-response, we need to verify:
        # Client sent: hash(password + challenge)
        # We verify by checking: hash(stored_password_hash + challenge) matches response
        
        # Actually, a better approach is:
        # Client hashes: hash(password + challenge)
        # We verify: compare with hash(password_from_db + challenge)
        # But we only have password_hash, so we use:
        # hash(stored_password_hash + challenge) as reference
        
        expected_response = hashlib.sha256(
            (user_record['password_hash'] + challenge).encode('utf-8')
        ).hexdigest()
        
        return response == expected_response


class AuthenticationSession:
    """
    Manages authentication session between Drone and Ground Station
    """
    
    def __init__(self):
        self.authenticator = PasswordAuthenticator()
        self.authenticated_users = {}  # {username: timestamp}
        self.active_challenges = {}  # {username: challenge}
    
    def register_drone(self, drone_id: str, password: str) -> dict:
        """Register a new drone with password"""
        return self.authenticator.register_user(drone_id, password)
    
    def initiate_authentication(self, drone_id: str) -> dict:
        """
        Initiate challenge-response authentication
        
        Args:
            drone_id: Drone identifier
            
        Returns:
            dict: {
                'status': 'success'/'error',
                'challenge': challenge_string
            }
        """
        if drone_id not in self.authenticator.user_db:
            return {
                'status': 'error',
                'message': f'Drone {drone_id} not registered'
            }
        
        challenge = self.authenticator.generate_challenge()
        self.active_challenges[drone_id] = challenge
        
        return {
            'status': 'success',
            'challenge': challenge
        }
    
    def authenticate_drone(self, drone_id: str, challenge_response: str) -> dict:
        """
        Authenticate drone based on challenge response
        
        Args:
            drone_id: Drone identifier
            challenge_response: Client's response to challenge
            
        Returns:
            dict: {
                'status': 'authenticated'/'failed',
                'message': '...',
                'auth_token': token_if_successful
            }
        """
        if drone_id not in self.active_challenges:
            return {
                'status': 'failed',
                'message': 'No active challenge for this drone'
            }
        
        challenge = self.active_challenges[drone_id]
        
        # Verify response
        if self.authenticator.verify_challenge_response(
            drone_id, challenge, challenge_response
        ):
            # Authentication successful
            auth_token = secrets.token_hex(32)
            self.authenticated_users[drone_id] = {
                'auth_token': auth_token,
                'authenticated_at': secrets.token_hex(8)  # Simplified timestamp
            }
            
            # Clean up challenge
            del self.active_challenges[drone_id]
            
            return {
                'status': 'authenticated',
                'message': f'Drone {drone_id} authenticated successfully',
                'auth_token': auth_token
            }
        else:
            return {
                'status': 'failed',
                'message': 'Invalid challenge response'
            }
    
    def verify_auth_token(self, drone_id: str, auth_token: str) -> bool:
        """
        Verify if authentication token is valid
        
        Args:
            drone_id: Drone identifier
            auth_token: Authentication token
            
        Returns:
            bool: True if valid, False otherwise
        """
        if drone_id not in self.authenticated_users:
            return False
        
        return self.authenticated_users[drone_id]['auth_token'] == auth_token


if __name__ == "__main__":
    # Demonstrate Authentication
    print("=" * 70)
    print("CHALLENGE-RESPONSE AUTHENTICATION DEMONSTRATION")
    print("=" * 70)
    
    # Initialize authentication session
    auth_session = AuthenticationSession()
    
    # Step 1: Register drone
    drone_id = "DR001"
    password = "SecurePassword123!"
    
    print(f"\n[Step 1] Registering Drone: {drone_id}")
    reg_result = auth_session.register_drone(drone_id, password)
    print(f"Result: {reg_result}")
    
    # Step 2: Initiate challenge
    print(f"\n[Step 2] Initiating Authentication Challenge")
    challenge_result = auth_session.initiate_authentication(drone_id)
    challenge = challenge_result['challenge']
    print(f"Challenge (first 16 chars): {challenge[:16]}...")
    
    # Step 3: Drone computes response
    print(f"\n[Step 3] Drone Computing Challenge Response")
    auth_obj = auth_session.authenticator
    salt = auth_obj.user_db[drone_id]['salt']
    password_hash = auth_obj.user_db[drone_id]['password_hash']
    
    # Drone computes: hash(password + challenge)
    drone_response = hashlib.sha256(
        (password_hash + challenge).encode('utf-8')
    ).hexdigest()
    print(f"Response (first 16 chars): {drone_response[:16]}...")
    
    # Step 4: Server verifies response
    print(f"\n[Step 4] Server Verifying Response")
    auth_result = auth_session.authenticate_drone(drone_id, drone_response)
    print(f"Result: {auth_result['status'].upper()}")
    print(f"Message: {auth_result['message']}")
    
    if auth_result['status'] == 'authenticated':
        print(f"Auth Token (first 16 chars): {auth_result['auth_token'][:16]}...")
        print("\n✓ Authentication Successful!")
    else:
        print("\n✗ Authentication Failed!")
    
    print("=" * 70)
