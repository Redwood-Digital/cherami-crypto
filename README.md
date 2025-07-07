# 🔐 Cherami Encryption Overview

**Cherami** is a privacy-first platform for encrypted, self-destructing messages and files — without storing any sensitive content on our servers.

This repository documents the encryption/decryption process used by Cherami to ensure transparency and build trust.

---

## 🔧 How Encryption Works

- Messages and files are encrypted *in the browser* using [AES-GCM 256-bit](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
- The decryption key **never leaves the client** — it's embedded in the shared link as a `#fragment`
- Optional password protection adds an extra layer using PBKDF2 key derivation
- The server only stores encrypted blobs and cannot decrypt them

---

## 🔑 Why This Matters

- 🔐 **Zero knowledge**: servers never see your content
- 🔒 **Password protection**: optional additional security layer  
- 📎 **File support**: client-side encryption for files up to 100MB
- 🧨 **Self-destructing**: content expires after chosen time or views
- 🏆 **Tier system**: Free, Whisper ($1.50/mo), and Echo ($7.50/mo) plans

---

## 📦 Files

### `encryption.js`
Client-side encryption implementation featuring:
- AES-GCM key generation
- Random IV generation  
- Message and file encryption
- Password-based key wrapping (PBKDF2)
- Base64 encoding for transmission

### `decrypt-demo.py`
Python example demonstrating the decryption process. This proves that **only someone with the key can decrypt** — which the server never has.

### `security-audit.md`
Detailed security analysis and third-party audit information.

---

## 🧪 Transparency

Audit this code to verify that Cherami:
- Encrypts everything client-side
- Never transmits plaintext or keys to servers
- Uses industry-standard encryption (AES-256-GCM)
- Implements secure key derivation (PBKDF2 with 100,000 iterations)

---

## 🔒 Password Protection

When a password is set:
1. A random salt is generated
2. PBKDF2 derives a wrapping key from the password
3. The message key is encrypted with this wrapping key
4. Decryption requires both the URL fragment AND the password

---

## 🧵 Learn More

- Visit [cherami.link/security](https://cherami.link/security) for our security whitepaper
- Try it at [cherami.link](https://cherami.link)
- API documentation at [cherami.link/api/docs](https://cherami.link/api/docs)