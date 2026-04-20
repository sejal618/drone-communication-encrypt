"""
Replay Attack Protection Module
Author: [Student Name - Customize this]
Date: April 2024
Purpose: Prevent attackers from replaying old valid messages

THE PROBLEM - REPLAY ATTACK:
Imagine this scenario:
  1. Drone sends: "FIRE_WEAPON, timestamp=10:00:00"
  2. Attacker intercepts the encrypted message
  3. Attacker replays it at 10:05:00
  4. If we don't check timestamp, system executes it again!

Other example - Drone command:
  1. "Increase altitude by 100m" (sent and verified)
  2. Attacker replays same message later
  3. Drone altitude increases again unexpectedly!

THE SOLUTION - DUAL MECHANISM:

1. TIMESTAMP VALIDATION:
   - Every message includes current timestamp
   - Receiver rejects messages older than 5 seconds
   - Prevents old recorded messages from being executed
   - Problem: What if clocks are slightly out of sync?
   
2. NONCE TRACKING:
   - Every message includes unique random nonce
   - Server tracks all nonces we've seen recently
   - If we see same nonce again, it's a replay!
   - Problem: Memory grows unbounded if not cleaned up

COMBINED APPROACH:
  Step 1: Check timestamp (fast rejection of old messages)
  Step 2: Check if nonce already seen (catch clever replays)
  Step 3: Add nonce to tracking set
  Step 4: Periodically clean old nonces (timestamp + buffer)

This gives us strong replay protection with minimal overhead.
"""

import time
import secrets
from typing import Dict


class ReplayProtection:
    """
    Prevents replay attacks using timestamps and nonces
    
    Mechanisms:
    1. Timestamp-based: Reject messages older than a threshold (5 seconds)
    2. Nonce-based: Track used nonces to prevent reuse
    
    Replay Attack: Attacker intercepts and replays old messages
    Example: Replay a "take off" command multiple times
    
    This class implements both mechanisms for robust protection.
    """
    
    def __init__(self, timestamp_tolerance: float = 5.0):
        """
        Initialize replay protection
        
        Args:
            timestamp_tolerance: Maximum age of message in seconds (default 5s)
        """
        self.timestamp_tolerance = timestamp_tolerance
        self.used_nonces = {}  # {nonce: timestamp_used}
        self.nonce_cleanup_threshold = 300  # Clean up old nonces after 5 minutes
    
    @staticmethod
    def generate_timestamp() -> float:
        """
        Generate current timestamp
        
        Returns:
            float: Current Unix timestamp
        """
        return time.time()
    
    @staticmethod
    def generate_nonce() -> str:
        """
        Generate a random nonce (cryptographically secure)
        
        Returns:
            str: Hex-encoded random nonce (32 bytes = 64 chars)
        """
        return secrets.token_hex(32)
    
    def is_timestamp_valid(self, message_timestamp: float) -> bool:
        """
        Check if message timestamp is within acceptable range
        
        Args:
            message_timestamp: Timestamp from message
            
        Returns:
            bool: True if timestamp is acceptable (not too old), False otherwise
        """
        current_time = self.generate_timestamp()
        time_diff = current_time - message_timestamp
        
        # Reject if message is too old
        if time_diff > self.timestamp_tolerance:
            return False
        
        # Reject if timestamp is in the future (clock skew up to 5 seconds allowed)
        if time_diff < -5:
            return False
        
        return True
    
    def is_nonce_valid(self, nonce: str) -> bool:
        """
        Check if nonce hasn't been used before
        
        Args:
            nonce: Nonce value to check
            
        Returns:
            bool: True if nonce is new (not seen before), False if already used
        """
        if nonce in self.used_nonces:
            return False  # Nonce already used
        
        # Record nonce usage
        self.used_nonces[nonce] = self.generate_timestamp()
        
        # Clean up old nonces to prevent memory bloat
        self._cleanup_old_nonces()
        
        return True
    
    def _cleanup_old_nonces(self):
        """Remove nonces older than cleanup threshold"""
        current_time = self.generate_timestamp()
        expired_nonces = [
            nonce for nonce, timestamp in self.used_nonces.items()
            if (current_time - timestamp) > self.nonce_cleanup_threshold
        ]
        for nonce in expired_nonces:
            del self.used_nonces[nonce]
    
    def validate_message(self, message_timestamp: float, nonce: str) -> Dict[str, str]:
        """
        Complete replay protection validation
        
        Args:
            message_timestamp: Timestamp from message
            nonce: Nonce from message
            
        Returns:
            dict: {
                'valid': bool,
                'reason': str (if not valid)
            }
        """
        # Check timestamp
        if not self.is_timestamp_valid(message_timestamp):
            return {
                'valid': False,
                'reason': 'Message timestamp too old or in future'
            }
        
        # Check nonce
        if not self.is_nonce_valid(nonce):
            return {
                'valid': False,
                'reason': 'Nonce already used (replay attack detected)'
            }
        
        return {
            'valid': True,
            'reason': 'Message passed replay protection checks'
        }


class ReplayProtectionManager:
    """
    Manages replay protection for the drone communication system
    """
    
    def __init__(self):
        self.protection = ReplayProtection(timestamp_tolerance=5.0)
    
    def generate_protection_tokens(self) -> Dict[str, str]:
        """
        Generate timestamp and nonce for a new message
        
        Returns:
            dict: {
                'timestamp': current_timestamp,
                'nonce': generated_nonce
            }
        """
        return {
            'timestamp': self.protection.generate_timestamp(),
            'nonce': self.protection.generate_nonce()
        }
    
    def check_message(self, timestamp: float, nonce: str) -> Dict[str, str]:
        """
        Check if message passes replay protection
        
        Args:
            timestamp: Message timestamp
            nonce: Message nonce
            
        Returns:
            dict: Validation result
        """
        return self.protection.validate_message(timestamp, nonce)


if __name__ == "__main__":
    # Demonstrate Replay Protection
    print("=" * 70)
    print("REPLAY ATTACK PROTECTION DEMONSTRATION")
    print("=" * 70)
    
    protection_mgr = ReplayProtectionManager()
    
    # Scenario 1: Valid message
    print("\n[Scenario 1] Valid Fresh Message")
    tokens = protection_mgr.generate_protection_tokens()
    timestamp = tokens['timestamp']
    nonce = tokens['nonce']
    
    print(f"Timestamp: {timestamp:.3f}")
    print(f"Nonce: {nonce[:16]}...")
    
    result = protection_mgr.check_message(timestamp, nonce)
    print(f"Result: {result['reason']}")
    
    # Scenario 2: Replay attack (same nonce)
    print("\n[Scenario 2] Replay Attack - Using Same Nonce")
    result_replay = protection_mgr.check_message(timestamp, nonce)
    print(f"Result: {result_replay['reason']}")
    
    # Scenario 3: Old message
    print("\n[Scenario 3] Old Message (timestamp too old)")
    old_timestamp = time.time() - 10  # 10 seconds ago
    new_nonce = protection_mgr.protection.generate_nonce()
    
    result_old = protection_mgr.check_message(old_timestamp, new_nonce)
    print(f"Result: {result_old['reason']}")
    
    # Scenario 4: Valid message with new nonce
    print("\n[Scenario 4] Valid Fresh Message (within tolerance)")
    tokens2 = protection_mgr.generate_protection_tokens()
    result_fresh = protection_mgr.check_message(tokens2['timestamp'], tokens2['nonce'])
    print(f"Result: {result_fresh['reason']}")
    
    print("\n✓ Replay protection system working correctly!")
    print("=" * 70)
