
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def generate_dh_keys():
    p = 23  
    g = 5   
    private_key = int.from_bytes(get_random_bytes(16), 'big') % p  
    public_key = pow(g, private_key, p)  
    return private_key, public_key, p, g

def derive_shared_key(private_key, peer_public_key, p):
    shared_secret = pow(peer_public_key, private_key, p)  
    return hashlib.sha512(str(shared_secret).encode()).digest()[:16]  


def compute_hash(message):
    hash_obj = hashlib.sha512()
    hash_obj.update(message.encode())
    return hash_obj.hexdigest()  


def encrypt_message(session_key, message):
    hash_code = compute_hash(message)
    
    combined_data = message + "***" + hash_code + "***"
    print("\nBefore Encryption:", combined_data)

    cipher = AES.new(session_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(combined_data.encode(), AES.block_size))
    return cipher.iv + ciphertext 


def decrypt_message(session_key, encrypted_data):
    iv = encrypted_data[:16] 
    ciphertext = encrypted_data[16:]
    
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

    
    if "***" in decrypted_data:
        message, received_hash, _ = decrypted_data.split("***")

        print("\nAfter Decryption:", message + "***" + received_hash + "***")

        expected_hash = compute_hash(message)
        if received_hash == expected_hash:
            print("Integrity Check Passed ")
            return message
        else:
            print("Integrity Check Failed ")
            return None
    else:
        print("Invalid message format ")
        return None


private_key_A, public_key_A, p, g = generate_dh_keys() 
private_key_B, public_key_B, _, _ = generate_dh_keys() 


session_key_A = derive_shared_key(private_key_A, public_key_B, p) 
session_key_B = derive_shared_key(private_key_B, public_key_A, p)  


message = input("Enter text: ")
encrypted_data = encrypt_message(session_key_A, message)
print("Encrypted Data:", encrypted_data.hex())

decrypted_message = decrypt_message(session_key_B, encrypted_data)
if decrypted_message:
    print("Final Decrypted Message:", decrypted_message)
