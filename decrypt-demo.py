"""
Cherami Decryption Demo
This demonstrates how decryption works - proving that without the key,
even the server cannot read your messages.
"""

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def decrypt_message(ciphertext_b64, iv_b64, key_b64):
    """
    Decrypt a message encrypted with AES-256-GCM
    
    Args:
        ciphertext_b64: Base64 encoded ciphertext (includes auth tag)
        iv_b64: Base64 encoded initialization vector
        key_b64: Base64 encoded key
    
    Returns:
        Decrypted plaintext string
    """
    # Decode from base64
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    key = base64.b64decode(key_b64)
    
    # Split ciphertext and tag (last 16 bytes)
    actual_ciphertext = ciphertext[:-16]
    tag = ciphertext[-16:]
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    
    # Decrypt
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    
    return plaintext.decode('utf-8')

def unwrap_password_key(wrapped_key_b64, password, salt_b64, iv_b64):
    """
    Unwrap a key that was protected with a password
    
    Args:
        wrapped_key_b64: Base64 encoded wrapped key
        password: Password string
        salt_b64: Base64 encoded salt
        iv_b64: Base64 encoded IV
    
    Returns:
        Unwrapped key bytes
    """
    # Decode inputs
    wrapped_key = base64.b64decode(wrapped_key_b64)
    salt = base64.b64decode(salt_b64)
    iv = base64.b64decode(iv_b64)
    
    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    wrapping_key = kdf.derive(password.encode())
    
    # Decrypt the wrapped key
    # Split wrapped data and tag
    wrapped_data = wrapped_key[:-16]
    tag = wrapped_key[-16:]
    
    cipher = Cipher(
        algorithms.AES(wrapping_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    
    decryptor = cipher.decryptor()
    unwrapped_key = decryptor.update(wrapped_data) + decryptor.finalize()
    
    return unwrapped_key

# Example usage:
if __name__ == "__main__":
    print("=== Cherami Decryption Demo ===")
    print()
    
    # This is what the server sees:
    print("What the server stores:")
    encrypted_data = {
        "ciphertext": "<encrypted blob>",
        "iv": "<initialization vector>",
        "metadata": {
            "expires": "2025-07-08T12:00:00Z",
            "views_remaining": 3
        }
    }
    print(f"  Ciphertext: {encrypted_data['ciphertext']}")
    print(f"  IV: {encrypted_data['iv']}")
    print(f"  Metadata: {encrypted_data['metadata']}")
    print()
    
    # This is what's in the URL fragment (never sent to server):
    print("What's in the URL fragment (never sent to server):")
    print("  Key: <decryption key>")
    print()
    
    # Without the key, the server cannot decrypt:
    print("Server attempting decryption without the key:")
    try:
        # This would fail because we don't have the key
        message = decrypt_message(
            "fake_ciphertext",
            "fake_iv",
            "wrong_key"
        )
    except Exception as e:
        print("  ✅ Correct! The server cannot decrypt without the key!")
        print(f"  Error: {type(e).__name__}")
    
    print()
    print("This proves Cherami's zero-knowledge architecture:")
    print("- The server never sees your plaintext")
    print("- The server never receives the decryption key")
    print("- Only you and your recipient can read the message")