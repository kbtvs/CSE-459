import socket
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def generate_dh_keys():
    p = 23  
    g = 5   
    private_key = int.from_bytes(os.urandom(16), 'big') % p
    public_key = pow(g, private_key, p)
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key, p):
    shared_secret = pow(peer_public_key, private_key, p)
    return hashlib.sha512(str(shared_secret).encode()).digest()[:16]  


def compute_hash(message):
    return hashlib.sha512(message.encode()).hexdigest()

def encrypt_message(session_key, message):
    hash_code = compute_hash(message)
    combined_data = message + "***" + hash_code + "***"
    
    print(f"\n[Client] Sending (Before Encryption): {combined_data}")

    cipher = AES.new(session_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(combined_data.encode(), AES.block_size))
    
    return cipher.iv + ciphertext  

def decrypt_message(session_key, encrypted_data):
    print(f"\n[Client] Received (Encrypted): {encrypted_data.hex()}")

    iv = encrypted_data[:16] 
    ciphertext = encrypted_data[16:]
    
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

    if "***" in decrypted_data:
        message, received_hash, _ = decrypted_data.split("***")

        print(f"\n[Client] Received (After Decryption): {message} | Hash: {received_hash}")

        
        expected_hash = compute_hash(message)
        if received_hash == expected_hash:
            print("[Client] Integrity Check ")
            return message
        else:
            print("[Client] Integrity Check ")
            return None
    else:
        print("[Client] Invalid message format ")
        return None


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 12345))

data = client_socket.recv(1024).decode()  
public_key_B, p, g = map(int, data.split(","))

private_key_A, public_key_A = generate_dh_keys()
client_socket.send(str(public_key_A).encode())  

session_key = derive_shared_key(private_key_A, public_key_B, p)
print("[Client] Shared AES Key Established ")


while True:
    message = input("[Client] Enter message: ")
    
    encrypted_data = encrypt_message(session_key, message)
    print(f"[Client] Sent (Encrypted): {encrypted_data.hex()}")
    client_socket.send(encrypted_data)

    encrypted_reply = client_socket.recv(4096)
    if not encrypted_reply:
        break

    decrypted_reply = decrypt_message(session_key, encrypted_reply)

print("[Client] Connection closed.")
client_socket.close()
