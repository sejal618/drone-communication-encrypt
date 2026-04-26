# Secure Drone Communication System

A Python implementation of a secure communication protocol between a Drone (Client) and Ground Control Station (Server), built for the Cryptography & Security course (AD310) at IIIT Raichur.

## Features

- **Diffie-Hellman Key Exchange** — shared secret established without prior knowledge
- **Hybrid Encryption** — RSA wraps AES session key; AES-256-CBC encrypts telemetry data
- **Password Authentication** — SHA-256 with random salt, constant-time comparison
- **Digital Signatures** — RSA-PSS signing and verification
- **Message Integrity** — HMAC-SHA256
- **Replay Attack Protection** — timestamp-based deduplication

## Project Structure
<img width="655" height="133" alt="image" src="https://github.com/user-attachments/assets/4f20cead-fe20-4a1c-9eab-be9a0b450214" />


## How to Run

```bash
pip install pycryptodome cryptography
python main.py
```

## Expected Output

- DH shared secret established
- Drone authenticated
- Telemetry encrypted, signed, and MAC'd
- Ground station verifies and decrypts
- Replay attack detected and rejected
