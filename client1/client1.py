import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac
import hashlib


def encrypt_with_aeli(plaintext, key1, key2, associated_data):
    # Generate a random nonce
    nonce = os.urandom(12)  # 96-bit nonce

    # Step 1: AES-GCM Encryption
    aesgcm = AESGCM(key1)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    # Step 2: HMAC Generation
    hmac_data = ciphertext + associated_data
    hmac_tag = hmac.new(key2, hmac_data, hashlib.sha256).digest()

    return ciphertext, nonce, hmac_tag


# Example usage
key1 = os.urandom(32)  # 256-bit encryption key
key2 = os.urandom(32)  # 256-bit HMAC key
associated_data = b"session_metadata"
plaintext = b"Sensitive data"
delimiter = b"<DELIM>"

with open('../client2/keys.txt', 'wb') as f:
    f.write(key1)
    f.write(delimiter)
    f.write(key2)

# Encrypt
ciphertext, nonce, hmac_tag = encrypt_with_aeli(plaintext, key1, key2, associated_data)

with open('../client2/file.txt', 'wb') as f:
    f.write(ciphertext)
    f.write(delimiter)
    f.write(nonce)
    f.write(delimiter)
    f.write(hmac_tag)
    f.write(delimiter)
    f.write(associated_data)

print("Key1:",key1)
print("Key2:",key2)
print("CipherText:",ciphertext)
print("Nonce:",nonce)
print("HMAC Tag:",hmac_tag)
print("Associated Data:",associated_data)



