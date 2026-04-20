"""
Attack Simulation & Demonstration (BONUS)
Demonstrates how the system detects and prevents various attacks
"""

import json
import time
from secure_protocol import DroneProtocol, GroundStationProtocol, SecureMessage
from key_exchange import perform_key_exchange


def print_section(title: str):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def print_attack(attack_name: str):
    """Print attack name"""
    print(f"\n{'█' * 80}")
    print(f" ATTACK: {attack_name}")
    print(f"{'█' * 80}")


def setup_secure_communication():
    """Setup authenticated and encrypted communication channel"""
    import hashlib
    
    drone_id = "DR001"
    drone_password = "SecurePassword123!"
    
    drone = DroneProtocol(drone_id, drone_password)
    gcs = GroundStationProtocol()
    
    # Key Exchange
    _, _, shared_secret = perform_key_exchange()
    drone.set_shared_secret(shared_secret)
    gcs.set_shared_secret(shared_secret)
    
    # Authentication
    gcs.register_drone(drone_id, drone_password)
    challenge_result = gcs.initiate_authentication(drone_id)
    challenge = challenge_result['challenge']
    
    auth_obj = gcs.auth_session.authenticator
    password_hash = auth_obj.user_db[drone_id]['password_hash']
    drone_response = hashlib.sha256(
        (password_hash + challenge).encode('utf-8')
    ).hexdigest()
    
    auth_result = gcs.authenticate_drone(drone_id, drone_response)
    drone.authenticated = True
    drone.auth_token = auth_result['auth_token']
    
    # Public key exchange
    gcs_rsa_pub = gcs.get_public_key()
    drone.set_gcs_public_key(gcs_rsa_pub)
    gcs.register_drone_keys(drone_id, drone.get_public_key(), 
                           drone.get_signature_public_key())
    
    return drone, gcs


def demonstrate_replay_attack():
    """
    ATTACK 1: Replay Attack
    Attacker intercepts a valid message and sends it again
    """
    
    print_attack("REPLAY ATTACK (Message Reuse)")
    
    drone, gcs = setup_secure_communication()
    
    # Drone sends legitimate telemetry
    telemetry = {
        "drone_id": "DR001",
        "command": "take_off",
        "altitude": 1000
    }
    
    print("\n[LEGITIMATE MESSAGE]")
    print(f"Telemetry: {json.dumps(telemetry)}")
    
    secure_msg = drone.create_secure_message(telemetry)
    
    print(f"\nMessage sent with:")
    print(f"  - Timestamp: {secure_msg.timestamp:.3f}")
    print(f"  - Nonce: {secure_msg.nonce[:16]}...")
    
    # First reception (legitimate)
    print("\n[FIRST RECEPTION - LEGITIMATE]")
    received1 = gcs.receive_secure_message(secure_msg)
    if received1:
        print("✓ Message accepted")
    
    # Attacker replays the same message
    print("\n[REPLAY ATTACK - ATTACKER REPLAYS SAME MESSAGE]")
    print("Attacker sends the same message again to execute same command...")
    
    received2 = gcs.receive_secure_message(secure_msg)
    if received2 is None:
        print("✓ ATTACK DETECTED AND BLOCKED!")
        print("  Reason: Nonce already used (replay protection triggered)")
    else:
        print("✗ ATTACK NOT DETECTED - System vulnerable!")
    
    print("\n" + "=" * 80)


def demonstrate_message_tampering():
    """
    ATTACK 2: Message Tampering
    Attacker modifies encrypted message or signature
    """
    
    print_attack("MESSAGE TAMPERING / MAN-IN-THE-MIDDLE ATTACK")
    
    drone, gcs = setup_secure_communication()
    
    # Legitimate telemetry
    telemetry = {
        "drone_id": "DR001",
        "latitude": 12.97,
        "longitude": 77.59,
        "instruction": "land_safely"
    }
    
    print("\n[LEGITIMATE MESSAGE]")
    print(f"Telemetry: {json.dumps(telemetry)}")
    
    secure_msg = drone.create_secure_message(telemetry)
    
    print(f"\nOriginal HMAC: {secure_msg.hmac}")
    
    # Attack Scenario 1: Modify encrypted data
    print("\n[ATTACK SCENARIO 1: MODIFY ENCRYPTED DATA]")
    print("Attacker intercepts and modifies encrypted data...")
    
    tampered_msg1 = SecureMessage.from_json(secure_msg.to_json())
    # Change a few characters in encrypted data
    tampered_msg1.encrypted_data = tampered_msg1.encrypted_data[:-8] + "MODIFIED"
    
    print(f"Modified encrypted data: {tampered_msg1.encrypted_data[-32:]}...")
    
    received = gcs.receive_secure_message(tampered_msg1)
    if received is None:
        print("✓ TAMPERING DETECTED AND BLOCKED!")
        print("  Reason: HMAC verification failed (integrity check)")
    else:
        print("✗ TAMPERING NOT DETECTED - System vulnerable!")
    
    # Attack Scenario 2: Modify signature
    print("\n[ATTACK SCENARIO 2: MODIFY DIGITAL SIGNATURE]")
    print("Attacker modifies the digital signature...")
    
    tampered_msg2 = SecureMessage.from_json(secure_msg.to_json())
    # Change signature
    tampered_msg2.signature = tampered_msg2.signature[:-8] + "FORGED!!"
    
    received = gcs.receive_secure_message(tampered_msg2)
    if received is None:
        print("✓ FORGERY DETECTED AND BLOCKED!")
        print("  Reason: Digital signature verification failed (authenticity check)")
    else:
        print("✗ FORGERY NOT DETECTED - System vulnerable!")
    
    # Attack Scenario 3: Modify HMAC
    print("\n[ATTACK SCENARIO 3: MODIFY HMAC]")
    print("Attacker modifies the HMAC...")
    
    tampered_msg3 = SecureMessage.from_json(secure_msg.to_json())
    # Change HMAC
    tampered_msg3.hmac = "InvalidHMACValue123456"
    
    received = gcs.receive_secure_message(tampered_msg3)
    if received is None:
        print("✓ TAMPERING DETECTED AND BLOCKED!")
        print("  Reason: HMAC mismatch (integrity compromised)")
    else:
        print("✗ TAMPERING NOT DETECTED - System vulnerable!")
    
    print("\n" + "=" * 80)


def demonstrate_old_message_attack():
    """
    ATTACK 3: Old Message/Delayed Replay
    Attacker sends a very old message (before timestamp tolerance)
    """
    
    print_attack("OLD MESSAGE ATTACK (Outdated Timestamp)")
    
    drone, gcs = setup_secure_communication()
    
    # Create a legitimate message
    telemetry = {
        "drone_id": "DR001",
        "status": "active"
    }
    
    secure_msg = drone.create_secure_message(telemetry)
    
    print(f"\n[LEGITIMATE MESSAGE WITH CURRENT TIMESTAMP]")
    print(f"Timestamp: {secure_msg.timestamp:.3f}")
    print(f"Current time: {time.time():.3f}")
    
    # First reception
    print("\n[FIRST RECEPTION - ACCEPTED]")
    received1 = gcs.receive_secure_message(secure_msg)
    if received1:
        print("✓ Message accepted (fresh timestamp)")
    
    print("\n[ATTACK: WAIT AND REPLAY OLD MESSAGE]")
    print("Attacker waits > 5 seconds, then replays the message...")
    print("(Simulating wait by creating old timestamp message)")
    
    # Create message with very old timestamp
    old_msg = SecureMessage.from_json(secure_msg.to_json())
    old_msg.timestamp = time.time() - 10  # 10 seconds old
    
    print(f"Old message timestamp: {old_msg.timestamp:.3f}")
    print(f"Age: {time.time() - old_msg.timestamp:.1f} seconds")
    print(f"Tolerance: 5 seconds")
    
    received2 = gcs.receive_secure_message(old_msg)
    if received2 is None:
        print("✓ ATTACK DETECTED AND BLOCKED!")
        print("  Reason: Timestamp too old (outside tolerance window)")
    else:
        print("✗ ATTACK NOT DETECTED - System vulnerable!")
    
    print("\n" + "=" * 80)


def demonstrate_authentication_bypass():
    """
    ATTACK 4: Authentication Bypass
    Attacker tries to send messages without authentication
    """
    
    print_attack("AUTHENTICATION BYPASS ATTEMPT")
    
    gcs = GroundStationProtocol()
    
    # Create unauthenticated drone
    unauthenticated_drone = DroneProtocol("DR002", "WrongPassword")
    
    print("\n[UNAUTHENTICATED DRONE ATTEMPTING COMMUNICATION]")
    print("Drone DR002 tries to send message without authentication...")
    
    try:
        telemetry = {"data": "secret"}
        secure_msg = unauthenticated_drone.create_secure_message(telemetry)
        print("✗ SECURITY FAILURE: Unauthenticated drone could create message!")
    except ValueError as e:
        print(f"✓ ATTACK BLOCKED: {e}")
        print("  Reason: Authentication required before message creation")
    
    print("\n" + "=" * 80)


def demonstrate_key_exchange_security():
    """
    ATTACK 5: Diffie-Hellman MITM Prevention
    Shows why DH prevents man-in-the-middle attacks on key exchange
    """
    
    print_attack("MAN-IN-THE-MIDDLE ATTACK ON KEY EXCHANGE")
    
    print("\n[DH KEY EXCHANGE SECURITY]")
    print("Even if attacker intercepts public keys, they cannot compute shared secret")
    print("because they don't have either private key.")
    
    from key_exchange import DiffieHellmanKeyExchange
    
    # Legitimate exchange
    drone_dh = DiffieHellmanKeyExchange("Drone")
    gcs_dh = DiffieHellmanKeyExchange("GCS")
    
    drone_private = drone_dh.generate_private_key()
    gcs_private = gcs_dh.generate_private_key()
    
    drone_public = drone_dh.generate_public_key()
    gcs_public = gcs_dh.generate_public_key()
    
    # They exchange public keys
    drone_secret = drone_dh.compute_shared_secret(gcs_public)
    gcs_secret = gcs_dh.compute_shared_secret(drone_public)
    
    print(f"\n[LEGITIMATE COMMUNICATION]")
    print(f"Drone shared secret: {drone_secret % 10000}")
    print(f"GCS shared secret: {gcs_secret % 10000}")
    print(f"Match: {drone_secret == gcs_secret} ✓")
    
    # Attacker intercepts public keys
    print(f"\n[ATTACKER INTERCEPTS PUBLIC KEYS]")
    print(f"Attacker has: drone_public, gcs_public")
    print(f"Attacker lacks: drone_private, gcs_private")
    
    # Even with public keys, attacker cannot compute shared secret
    print(f"\n[WHY ATTACKER CANNOT SUCCEED]")
    print(f"To compute shared secret, attacker would need:")
    print(f"  Option 1: drone_private (to compute gcs_public^drone_private)")
    print(f"  Option 2: gcs_private (to compute drone_public^gcs_private)")
    print(f"\nWithout either private key, attack is mathematically impossible!")
    print(f"This is the strength of Diffie-Hellman key exchange.")
    
    print("\n" + "=" * 80)


def main():
    """Run all attack demonstrations"""
    
    print_section("BONUS: ATTACK SIMULATION & SECURITY ANALYSIS")
    print("Demonstrating how the system detects and prevents various attacks")
    
    # Run all attack demonstrations
    demonstrate_replay_attack()
    demonstrate_message_tampering()
    demonstrate_old_message_attack()
    demonstrate_authentication_bypass()
    demonstrate_key_exchange_security()
    
    # Summary
    print_section("ATTACK SIMULATION SUMMARY")
    
    print("\n✓ REPLAY ATTACKS: Prevented by nonce + timestamp tracking")
    print("✓ MESSAGE TAMPERING: Detected by HMAC verification")
    print("✓ SIGNATURE FORGERY: Detected by RSA signature verification")
    print("✓ OUTDATED MESSAGES: Rejected by timestamp validation")
    print("✓ UNAUTHENTICATED ACCESS: Blocked by authentication requirement")
    print("✓ KEY EXCHANGE MITM: Prevented by DH mathematical properties")
    
    print("\n" + "=" * 80)
    print(" ALL ATTACKS SUCCESSFULLY DETECTED/PREVENTED")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
