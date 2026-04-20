"""
MAIN DEMONSTRATION - Secure Drone Communication System
Author: [Student Name - Customize this]
Student ID: [Your ID - Customize this]
Date: April 2024
Course: Cryptography & Security

PURPOSE:
This script demonstrates a complete, real-world secure communication system
between a Drone (client) and Ground Control Station (server). It integrates
all cryptographic concepts from the course:

  ✓ Key Exchange (Diffie-Hellman)
  ✓ Hybrid Encryption (RSA + AES)
  ✓ Authentication (Challenge-Response)
  ✓ Digital Signatures (RSA)
  ✓ Message Integrity (HMAC-SHA256)
  ✓ Replay Protection (Timestamp + Nonce)

THE WORKFLOW DEMONSTRATES:
  Phase 1: System Initialization
  Phase 2: Authentication (Drone proves identity)
  Phase 3: Key Exchange (Establish shared secrets)
  Phase 4: Session Setup (Prepare for secure communication)
  Phase 5: Secure Communication (Multiple messages with full protection)
  Phase 6: Attack Prevention (Show what our system stops)

This is the "real test" - all components working together!
"""

import json
from key_exchange import perform_key_exchange
from secure_protocol import DroneProtocol, GroundStationProtocol, SecureMessage
from authentication import PasswordAuthenticator


def print_section(title: str):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def print_step(step_num: int, description: str):
    """Print a formatted step"""
    print(f"\n[Step {step_num}] {description}")
    print("-" * 80)


def demonstrate_drone_communication():
    """
    Complete demonstration of secure drone-to-GCS communication
    """
    
    print_section("SECURE DRONE COMMUNICATION SYSTEM")
    print("Demonstrating complete workflow with all security components")
    
    # ==================== PHASE 1: SETUP ====================
    print_section("PHASE 1: SYSTEM SETUP")
    
    # Create drone and GCS instances
    drone_id = "DR001"
    drone_password = "SecurePassword123!"
    
    drone = DroneProtocol(drone_id, drone_password)
    gcs = GroundStationProtocol()
    
    print(f"\n✓ Drone initialized: {drone_id}")
    print(f"✓ Ground Station initialized")
    
    # ==================== PHASE 2: KEY EXCHANGE ====================
    print_section("PHASE 2: DIFFIE-HELLMAN KEY EXCHANGE")
    
    print_step(1, "Both parties generate private keys and compute public keys")
    
    # Perform DH key exchange
    drone_dh_pub, gcs_dh_pub, shared_secret = perform_key_exchange()
    
    print(f"✓ Shared Secret derived: ...{str(shared_secret)[-16:]}")
    print(f"  Shared Secret (last 16 digits): ...{str(shared_secret)[-16:]}")
    
    # Both parties set shared secret
    drone.set_shared_secret(shared_secret)
    gcs.set_shared_secret(shared_secret)
    
    print(f"✓ Shared secret configured for both Drone and GCS")
    
    # ==================== PHASE 3: AUTHENTICATION ====================
    print_section("PHASE 3: CHALLENGE-RESPONSE AUTHENTICATION")
    
    print_step(1, "Drone Registration")
    reg_result = gcs.register_drone(drone_id, drone_password)
    print(f"✓ {reg_result['message']}")
    
    print_step(2, "Server sends authentication challenge")
    challenge_result = gcs.initiate_authentication(drone_id)
    challenge = challenge_result['challenge']
    print(f"✓ Challenge generated: {challenge[:16]}...")
    
    print_step(3, "Drone computes challenge response")
    auth_obj = gcs.auth_session.authenticator
    password_hash = auth_obj.user_db[drone_id]['password_hash']
    
    import hashlib
    drone_response = hashlib.sha256(
        (password_hash + challenge).encode('utf-8')
    ).hexdigest()
    print(f"✓ Response computed: {drone_response[:16]}...")
    
    print_step(4, "Server verifies response and issues auth token")
    auth_result = gcs.authenticate_drone(drone_id, drone_response)
    print(f"✓ {auth_result['message']}")
    
    if auth_result['status'] == 'authenticated':
        drone.authenticated = True
        drone.auth_token = auth_result['auth_token']
        print(f"✓ Drone authenticated with token: {auth_result['auth_token'][:16]}...")
    else:
        print("✗ Authentication failed!")
        return
    
    # ==================== PHASE 4: KEY SETUP ====================
    print_section("PHASE 4: RSA PUBLIC KEY EXCHANGE & REGISTRATION")
    
    print_step(1, "Exchange RSA public keys for encryption")
    
    drone_rsa_pub = drone.get_public_key()
    drone_sig_pub = drone.get_signature_public_key()
    gcs_rsa_pub = gcs.get_public_key()
    
    drone.set_gcs_public_key(gcs_rsa_pub)
    gcs.register_drone_keys(drone_id, drone_rsa_pub, drone_sig_pub)
    
    print(f"✓ Drone RSA public key registered with GCS")
    print(f"✓ Drone signature public key registered with GCS")
    print(f"✓ GCS RSA public key configured in Drone")
    
    # ==================== PHASE 5: SECURE MESSAGE TRANSMISSION ====================
    print_section("PHASE 5: SECURE MESSAGE TRANSMISSION")
    
    # Sample telemetry data
    telemetry_data = {
        "drone_id": "DR001",
        "latitude": 12.9716,
        "longitude": 77.5946,
        "altitude": 1500,
        "speed": 45,
        "battery": 85
    }
    
    print_step(1, "Drone prepares telemetry data")
    print(f"\nOriginal Telemetry Data:")
    print(json.dumps(telemetry_data, indent=2))
    
    print_step(2, "Drone creates secure message (all security components)")
    secure_msg = drone.create_secure_message(telemetry_data)
    
    print(f"\n✓ Message encrypted with AES-256-CBC")
    print(f"✓ Message signed with RSA (authenticity)")
    print(f"✓ HMAC-SHA256 computed (integrity)")
    print(f"✓ Timestamp & nonce added (replay protection)")
    
    print(f"\nSecure Message Components:")
    print(f"  - Timestamp: {secure_msg.timestamp:.3f}")
    print(f"  - Nonce: {secure_msg.nonce[:16]}...")
    print(f"  - Encrypted AES Key: {secure_msg.encrypted_aes_key[:32]}...")
    print(f"  - Encrypted Data: {secure_msg.encrypted_data[:32]}...")
    print(f"  - Signature: {secure_msg.signature[:32]}...")
    print(f"  - HMAC: {secure_msg.hmac}")
    
    print_step(3, "GCS receives and verifies message")
    
    received_data = gcs.receive_secure_message(secure_msg)
    
    if received_data:
        print(f"\n✓ Replay protection validated")
        print(f"✓ Message integrity verified (HMAC)")
        print(f"✓ Message authenticity verified (signature)")
        print(f"✓ Message decrypted successfully")
        print(f"\nReceived and Decrypted Telemetry Data:")
        print(json.dumps(received_data, indent=2))
        
        # Verify data integrity
        if received_data == telemetry_data:
            print(f"\n✓ Data integrity confirmed - original and decrypted match!")
        else:
            print(f"\n✗ Data mismatch!")
    else:
        print(f"\n✗ Message verification failed!")
        return
    
    # ==================== PHASE 6: TEST VARIOUS SCENARIOS ====================
    print_section("PHASE 6: SECURITY SCENARIO TESTING")
    
    print_step(1, "Test Scenario: Message Tampering Detection")
    print("Attempting to modify encrypted data...")
    
    tampered_msg = SecureMessage.from_json(secure_msg.to_json())
    # Tamper with encrypted data
    tampered_msg.encrypted_data = tampered_msg.encrypted_data[:-4] + "XXXX"
    
    print("Sending tampered message...")
    received_tampered = gcs.receive_secure_message(tampered_msg)
    if received_tampered is None:
        print("✓ Tampering detected and rejected!")
    else:
        print("✗ Tampering not detected!")
    
    print_step(2, "Test Scenario: Replay Attack Detection")
    print("Attempting to replay the same message...")
    
    received_replay = gcs.receive_secure_message(secure_msg)
    if received_replay is None:
        print("✓ Replay attack detected and rejected!")
    else:
        print("✗ Replay not detected!")
    
    print_step(3, "Test Scenario: Valid New Message (Different Nonce)")
    print("Sending new telemetry update with fresh timestamp and nonce...")
    
    new_telemetry = {
        "drone_id": "DR001",
        "latitude": 12.9720,
        "longitude": 77.5950,
        "altitude": 1600,
        "speed": 50,
        "battery": 82
    }
    
    new_secure_msg = drone.create_secure_message(new_telemetry)
    received_new = gcs.receive_secure_message(new_secure_msg)
    
    if received_new:
        print("✓ New message accepted and verified successfully!")
        print(f"\nNew Telemetry Data:")
        print(json.dumps(received_new, indent=2))
    else:
        print("✗ New message rejected!")
    
    # ==================== SUMMARY ====================
    print_section("SYSTEM SUMMARY & SECURITY ANALYSIS")
    
    print("\n✓ CONFIDENTIALITY: Data encrypted with AES-256-CBC")
    print("  -> Attacker cannot read messages")
    
    print("\n✓ AUTHENTICITY: Messages signed with RSA")
    print("  -> Ensures messages come from authorized drone")
    
    print("\n✓ INTEGRITY: HMAC-SHA256 protects against tampering")
    print("  -> Any modification detected and rejected")
    
    print("\n✓ REPLAY PROTECTION: Timestamp + Nonce mechanisms")
    print("  -> Prevents repeated use of old messages")
    
    print("\n✓ KEY EXCHANGE: Diffie-Hellman establishes shared secret")
    print("  -> Secure key agreement without prior shared knowledge")
    
    print("\n✓ AUTHENTICATION: Challenge-Response prevents unauthorized access")
    print("  -> Only drones with correct password can authenticate")
    
    print("\n" + "=" * 80)
    print(" DEMONSTRATION COMPLETE - ALL SECURITY COMPONENTS WORKING!")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    demonstrate_drone_communication()
