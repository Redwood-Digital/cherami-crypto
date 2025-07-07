# Cherami Security Audit

## Overview
This document provides a security analysis of Cherami's encryption implementation.

## Encryption Standards
- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Generation**: Web Crypto API's secure random generator
- **IV Generation**: 96-bit random nonce per message
- **Password KDF**: PBKDF2-SHA256 with 100,000 iterations

## Security Properties
1. **Forward Secrecy**: Each message uses a unique key
2. **Authentication**: GCM mode prevents tampering
3. **Key Isolation**: Keys never touch the server
4. **Password Strength**: PBKDF2 slows brute force attacks

## Implementation Details

### Key Generation
```javascript
// Each message gets a unique 256-bit key
const key = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  true,
  ["encrypt", "decrypt"]
);
```

### Password Protection
When a password is used:
1. Generate 128-bit salt
2. Derive wrapping key using PBKDF2 (100,000 iterations)
3. Wrap message key with AES-GCM
4. Store wrapped key + salt + IV

### URL Structure
```
https://cherami.link/m/[message_id]#[base64_key_data]
                    ^              ^
                    |              |
            Sent to server    Never sent to server
```

## Threat Model

### Protected Against
- Server compromise (zero-knowledge)
- Network eavesdropping (HTTPS + client encryption)
- Brute force attacks (PBKDF2 iterations)
- Tampering (GCM authentication)

### Not Protected Against
- Compromised client device
- Weak passwords (user responsibility)
- Social engineering
- Quantum computers (future consideration)

## Third-Party Audits
*Pending - planned for Q2 2025*

## Responsible Disclosure
Security issues: security@cherami.link
PGP Key: [Coming Soon]

## Bug Bounty Program
*Coming Soon - Q2 2025*