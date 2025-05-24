\# 🔐 LinkVault Encryption Overview

\*\*LinkVault\*\* allows users to send encrypted, self-destructing messages — without storing any sensitive content on a server.

This repo documents the exact encryption/decryption process used by LinkVault to ensure transparency and build trust.

\---

\#\# 🔧 How Encryption Works

\- Messages are encrypted \*in the browser\* using \[AES-GCM 256-bit\](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt).  
\- The decryption key \*\*never leaves the client\*\* — it’s embedded in the shared link as a \`\#fragment\`.  
\- The server only sees and stores the encrypted blob (ciphertext) and cannot decrypt it.

\---

\#\# 🔑 Why This Matters

\- 🔐 \*\*Zero knowledge\*\*: the server never sees the message  
\- 👁️‍🗨️ \*\*No tracking\*\*: no accounts, no IP logs, no cookies  
\- 🧨 \*\*Self-destructing\*\*: messages expire after a chosen time or number of views

\---

\#\# 📦 Files

\#\#\# \`encryption.js\`  
This snippet runs in-browser and performs:

\- AES-GCM key generation  
\- Random IV generation  
\- Encryption of the message  
\- Base64 encoding

\#\#\# \`decrypt-snippet.py\`  
Python example that shows how the server \*could\* decrypt if it had the key — which it never does. This proves that \*\*only the client can decrypt\*\*.

\---

\#\# 🧪 Transparency

You can audit this code to verify that LinkVault is:

\- Encrypting client-side  
\- Never storing or transmitting plaintext  
\- Embedding the key only in the link hash (which browsers never send to the server)

\---

\#\# 🧵 Learn More

Visit \[linkvault.xyz/security\](https://linkvault.xyz/security) to understand how your data stays secure.

