# Python Decryption Sample (for transparency/demo only)


import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decrypt_message(encoded_key, encoded_iv, encoded_cipher):
    key = base64.b64decode(encoded_key)
    iv = base64.b64decode(encoded_iv)
    ciphertext = base64.b64decode(encoded_cipher)


    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")