import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac
import hashlib

def decrypt_with_aeli(ciphertext, nonce, hmac_tag, key1, key2, associated_data):
    # Step 1: Verify HMAC
    hmac_data = ciphertext + associated_data
    computed_hmac = hmac.new(key2, hmac_data, hashlib.sha256).digest()
    if not hmac.compare_digest(hmac_tag, computed_hmac):
        raise ValueError("HMAC verification failed!")

    # Step 2: AES-GCM Decryption
    aesgcm = AESGCM(key1)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)

    return plaintext

# Decrypt

delimiter = b"<DELIM>"

with open('keys.txt', 'rb') as f:
    keys = f.read()
    key1, key2 = keys.split(delimiter)


with open('file.txt', 'rb') as f:
    data = f.read()
    ciphertext, nonce, hmac_tag, associated_data = data.split(delimiter)

print("Key1:",key1)
print("Key2:",key2)
print("CipherText:",ciphertext)
print("Nonce:",nonce)
print("HMAC Tag:",hmac_tag)
print("Associated Data:",associated_data)

decrypted_plaintext = decrypt_with_aeli(ciphertext, nonce, hmac_tag, key1, key2, associated_data)
print("Decrypted plaintext:", decrypted_plaintext)