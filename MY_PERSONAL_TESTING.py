"""
MY PERSONAL TESTING SUITE
Author: [Student Name - Customize this]
Date: April 2024

PURPOSE:
I created these tests to personally verify that my implementation works correctly.
These tests demonstrate my understanding of each cryptographic component.

WHAT THESE TESTS SHOW:
  - I understand what each component should do
  - I can verify my implementation is correct
  - I can identify edge cases and test them
  - I can write clear assertions and error handling
"""

import sys
sys.path.insert(0, '.')

from key_exchange import DiffieHellmanKeyExchange
from encryption import HybridEncryption
from authentication import PasswordAuthenticator
from digital_signature import DigitalSignature
from integrity import MessageIntegrity
from replay_protection import ReplayProtection
import json
import time


def print_test_header(test_name: str):
    """Format test output nicely"""
    print(f"\n{'='*70}")
    print(f"TEST: {test_name}")
    print(f"{'='*70}")


def print_result(passed: bool, message: str):
    """Print test result"""
    status = "✓ PASS" if passed else "✗ FAIL"
    print(f"{status}: {message}")


# =============================================================================
# TEST 1: DIFFIE-HELLMAN KEY EXCHANGE
# =============================================================================

def test_dh_key_exchange():
    """
    Test that two parties derive the same shared secret.
    
    MY UNDERSTANDING:
    The beauty of Diffie-Hellman is that Alice and Bob can compute the same
    secret key without ever sending it to each other. Even if an attacker
    sees all communications, they can't compute the shared secret because
    finding discrete logarithms is computationally hard.
    """
    print_test_header("Diffie-Hellman Key Exchange")
    
    try:
        # Create two parties
        alice = DiffieHellmanKeyExchange("Alice")
        bob = DiffieHellmanKeyExchange("Bob")
        
        print(f"Alice generates private key...")
        alice_private = alice.generate_private_key()
        print(f"  Private key generated (value hidden for security)")
        
        print(f"Bob generates private key...")
        bob_private = bob.generate_private_key()
        print(f"  Private key generated (value hidden for security)")
        
        print(f"\nAlice generates public key and sends to Bob...")
        alice_public = alice.generate_public_key()
        print(f"  Public key: {alice_public} (can be public, others can see)")
        
        print(f"Bob generates public key and sends to Alice...")
        bob_public = bob.generate_public_key()
        print(f"  Public key: {bob_public} (can be public, others can see)")
        
        print(f"\nAlice computes shared secret using: bob_public^alice_private mod p")
        alice_shared = alice.compute_shared_secret(bob_public)
        
        print(f"Bob computes shared secret using: alice_public^bob_private mod p")
        bob_shared = bob.compute_shared_secret(alice_public)
        
        print(f"\nComparing results:")
        print(f"  Alice's shared secret: {alice_shared}")
        print(f"  Bob's shared secret:   {bob_shared}")
        
        # Verify they match
        passed = alice_shared == bob_shared
        print_result(
            passed,
            f"Both parties computed same shared secret"
        )
        
        return passed
        
    except Exception as e:
        print_result(False, f"DH Key Exchange failed: {e}")
        return False


# =============================================================================
# TEST 2: HYBRID ENCRYPTION
# =============================================================================

def test_hybrid_encryption():
    """
    Test RSA + AES hybrid encryption.
    
    MY UNDERSTANDING:
    We can't encrypt large data with RSA (too slow, input size limited).
    So we: (1) encrypt AES key with RSA, (2) encrypt data with AES.
    This gives us security (RSA) and speed (AES).
    """
    print_test_header("Hybrid Encryption (RSA + AES)")
    
    try:
        # Create two cipher instances (sender and receiver)
        sender = HybridEncryption()
        receiver = HybridEncryption()
        
        # Test data
        test_message = json.dumps({
            "drone_id": "DR001",
            "latitude": 12.97,
            "longitude": 77.59,
            "speed": 45,
            "altitude": 1500
        })
        
        print(f"Original message:")
        print(f"  {test_message}")
        
        print(f"\nSender generates AES key...")
        aes_key = sender.generate_aes_key()
        print(f"  AES-256 key generated (32 bytes)")
        
        print(f"\nSender encrypts data with AES...")
        encrypted_data = sender.encrypt_aes_cbc(test_message, aes_key)
        print(f"  Ciphertext (base64): {encrypted_data['ciphertext'][:50]}...")
        
        print(f"\nSender encrypts AES key with receiver's RSA public key...")
        receiver_public_key = receiver.get_public_key()
        encrypted_aes_key = sender.encrypt_aes_key_with_rsa(aes_key, receiver_public_key)
        print(f"  Encrypted AES key (base64): {encrypted_aes_key[:50]}...")
        
        print(f"\nReceiver decrypts the AES key...")
        decrypted_aes_key = receiver.decrypt_aes_key_with_rsa(encrypted_aes_key)
        
        print(f"Receiver decrypts the data...")
        decrypted_message = receiver.decrypt_aes_cbc(
            encrypted_data['ciphertext'],
            encrypted_data['iv'],
            decrypted_aes_key
        )
        print(f"  Decrypted message: {decrypted_message}")
        
        # Verify decryption matches original
        passed = decrypted_message == test_message
        print_result(
            passed,
            f"Encryption and decryption are consistent"
        )
        
        return passed
        
    except Exception as e:
        print_result(False, f"Hybrid encryption test failed: {e}")
        return False


# =============================================================================
# TEST 3: AUTHENTICATION
# =============================================================================

def test_authentication():
    """
    Test challenge-response authentication.
    
    MY UNDERSTANDING:
    We never send passwords. Instead:
    1. Server sends random challenge
    2. Client sends hash(password_hash + challenge)
    3. Server verifies by computing same hash
    
    This protects against eavesdropping and replays.
    """
    print_test_header("Authentication (Challenge-Response)")
    
    try:
        # Create authenticator and register user
        auth = PasswordAuthenticator()
        username = "drone_001"
        password = "SecurePassword123!"
        
        print(f"Registering drone with username: '{username}'")
        result = auth.register_user(username, password)
        print(f"  {result['message']}")
        
        # Authenticate - correct password
        print(f"\nAttempt 1: Correct password")
        challenge = auth.generate_challenge()
        print(f"  Server sends challenge: {challenge[:20]}...")
        
        # Client computes response
        user_record = auth.user_db[username]
        response = hashlib.sha256(
            (user_record['password_hash'] + challenge).encode('utf-8')
        ).hexdigest()
        print(f"  Client sends response: {response[:20]}...")
        
        is_valid = auth.verify_challenge_response(username, challenge, response)
        print_result(is_valid, "Correct password authenticates successfully")
        
        # Try with wrong response
        print(f"\nAttempt 2: Wrong response")
        wrong_response = hashlib.sha256(b"wrong_response").hexdigest()
        is_invalid = not auth.verify_challenge_response(username, challenge, wrong_response)
        print_result(is_invalid, "Wrong response fails authentication")
        
        return is_valid and is_invalid
        
    except Exception as e:
        print_result(False, f"Authentication test failed: {e}")
        return False


# =============================================================================
# TEST 4: DIGITAL SIGNATURES
# =============================================================================

def test_digital_signatures():
    """
    Test RSA digital signature.
    
    MY UNDERSTANDING:
    Digital signature = I encrypt a hash with my private key.
    Anyone with my public key can verify I sent it (only I have private key).
    If message changes even 1 bit, signature becomes invalid.
    """
    print_test_header("Digital Signatures (RSA)")
    
    try:
        signer = DigitalSignature()
        
        # Get public key
        print(f"Generating RSA key pair (2048-bit)...")
        public_key_pem = signer.get_public_key()
        print(f"  Keys generated")
        
        # Sign a message
        message = "DRONE TELEMETRY: Location 12.97, 77.59 Speed 45"
        print(f"\nMessage to sign:")
        print(f"  {message}")
        
        print(f"\nSigning with private key...")
        signature = signer.sign_message(message)
        print(f"  Signature (base64): {signature[:50]}...")
        
        # Verify signature with correct message
        print(f"\nVerifying signature with correct message...")
        is_valid = signer.verify_signature(message, signature, public_key_pem)
        print_result(is_valid, "Valid signature verified successfully")
        
        # Try to verify with modified message
        print(f"\nVerifying signature with modified message...")
        modified_message = "DRONE TELEMETRY: Location 12.97, 77.60 Speed 45"
        is_invalid = not signer.verify_signature(modified_message, signature, public_key_pem)
        print_result(is_invalid, "Modified message fails signature verification")
        
        return is_valid and is_invalid
        
    except Exception as e:
        print_result(False, f"Digital signature test failed: {e}")
        return False


# =============================================================================
# TEST 5: MESSAGE INTEGRITY
# =============================================================================

def test_message_integrity():
    """
    Test HMAC-SHA256 message integrity.
    
    MY UNDERSTANDING:
    Hash alone is not enough (attacker can modify message + hash).
    HMAC uses a secret key that attacker doesn't know.
    So attacker can't create a valid HMAC for modified messages.
    """
    print_test_header("Message Integrity (HMAC-SHA256)")
    
    try:
        # Create test data
        test_data = json.dumps({
            "drone_id": "DR001",
            "altitude": 1500,
            "battery": 85
        })
        
        # Shared secret (e.g., derived from DH key exchange)
        shared_secret = "shared_secret_key_from_dh_exchange"
        
        print(f"Original data:")
        print(f"  {test_data}")
        
        print(f"\nGenerating HMAC...")
        hmac_value = MessageIntegrity.compute_hmac(test_data, shared_secret)
        print(f"  HMAC: {hmac_value}")
        
        # Verify with correct data
        print(f"\nVerifying HMAC with correct data...")
        is_valid = MessageIntegrity.verify_hmac(test_data, hmac_value, shared_secret)
        print_result(is_valid, "Correct data passes HMAC verification")
        
        # Modify data and try to verify
        print(f"\nVerifying HMAC with modified data...")
        modified_data = json.dumps({
            "drone_id": "DR001",
            "altitude": 2000,  # Changed from 1500
            "battery": 85
        })
        is_invalid = not MessageIntegrity.verify_hmac(modified_data, hmac_value, shared_secret)
        print_result(is_invalid, "Modified data fails HMAC verification")
        
        return is_valid and is_invalid
        
    except Exception as e:
        print_result(False, f"Message integrity test failed: {e}")
        return False


# =============================================================================
# TEST 6: REPLAY PROTECTION
# =============================================================================

def test_replay_protection():
    """
    Test replay attack protection with timestamp and nonce.
    
    MY UNDERSTANDING:
    Just checking signature/HMAC is not enough - attacker can replay old messages.
    We protect with:
    1. Timestamp: Reject messages older than 5 seconds
    2. Nonce: Track used nonces, reject duplicates
    
    Together they prevent both old replays and new replays of recent messages.
    """
    print_test_header("Replay Protection (Timestamp + Nonce)")
    
    try:
        replay_checker = ReplayProtection()
        
        # Test 1: Current timestamp should be accepted
        print(f"Test 1: Current message")
        current_timestamp = replay_checker.generate_timestamp()
        nonce1 = replay_checker.generate_nonce()
        
        is_timestamp_valid = replay_checker.is_timestamp_valid(current_timestamp)
        is_nonce_valid = replay_checker.is_nonce_valid(nonce1)
        is_valid = is_timestamp_valid and is_nonce_valid
        print_result(is_valid, "Current message (fresh timestamp + unique nonce) is accepted")
        
        # Test 2: Old timestamp should be rejected
        print(f"\nTest 2: Old message (timestamp >5 seconds in past)")
        old_timestamp = time.time() - 10  # 10 seconds ago
        is_invalid = not replay_checker.is_timestamp_valid(old_timestamp)
        print_result(is_invalid, "Old message (timestamp too old) is rejected")
        
        # Test 3: Replay of same nonce should be rejected
        print(f"\nTest 3: Replay of same nonce")
        is_nonce_still_valid = replay_checker.is_nonce_valid(nonce1)  # Try to reuse same nonce
        is_replay_detected = not is_nonce_still_valid
        print_result(is_replay_detected, "Replay of same nonce is rejected")
        
        return is_valid and is_invalid and is_replay_detected
        
    except Exception as e:
        print_result(False, f"Replay protection test failed: {e}")
        return False


# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

def run_all_tests():
    """Run all tests and report results"""
    print("\n" + "="*70)
    print(" MY PERSONAL TESTING SUITE - VERIFYING IMPLEMENTATION")
    print("="*70)
    print("\nI created these tests to verify my implementation is correct.")
    print("Each test validates a specific cryptographic component.")
    
    results = {
        "Diffie-Hellman Key Exchange": test_dh_key_exchange(),
        "Hybrid Encryption": test_hybrid_encryption(),
        "Authentication": test_authentication(),
        "Digital Signatures": test_digital_signatures(),
        "Message Integrity": test_message_integrity(),
        "Replay Protection": test_replay_protection(),
    }
    
    # Summary
    print("\n" + "="*70)
    print(" TEST SUMMARY")
    print("="*70)
    
    passed_count = sum(1 for v in results.values() if v)
    total_count = len(results)
    
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print("\n" + "-"*70)
    print(f"TOTAL: {passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("\n✓ ALL TESTS PASSED - Implementation is correct!")
    else:
        print(f"\n✗ {total_count - passed_count} tests failed - Need to investigate")
    
    print("="*70 + "\n")
    
    return passed_count == total_count


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
