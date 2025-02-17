from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def gen_key():
    return get_random_bytes(16)

def encrypt_text(file, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(file, 'rb') as f:
        data = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce, ciphertext, tag
    
def decrypt_text(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data
    except ValueError:
        print("Decryption failed! Invalid key or corrupted data.")
        return None
    
input_file = input("Enter the file name: ")
key = gen_key()
nonce, encrypted_data, tag = encrypt_text(input_file, key)
print(f"Encrypted data: {encrypted_data}")
decrypted_data = decrypt_text(nonce, encrypted_data, tag, key)
if decrypted_data:
    print(f"Decrypted data: {decrypted_data}")
else:
    print("Decryption failed.")