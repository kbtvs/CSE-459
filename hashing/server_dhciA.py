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
    return private_key, public_key, p, g

def derive_shared_key(private_key, peer_public_key, p):
    shared_secret = pow(peer_public_key, private_key, p)
    return hashlib.sha512(str(shared_secret).encode()).digest()[:16]  


def compute_hash(message):
    return hashlib.sha512(message.encode()).hexdigest()

def encrypt_message(session_key, message):
    hash_code = compute_hash(message)
    combined_data = message + "***" + hash_code + "***"
    
    print(f"\n[Server] Sending (Before Encryption): {combined_data}")

    cipher = AES.new(session_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(combined_data.encode(), AES.block_size))
    
    return cipher.iv + ciphertext  

def decrypt_message(session_key, encrypted_data):
    print(f"\n[Server] Received (Encrypted): {encrypted_data.hex()}")

    iv = encrypted_data[:16]  
    ciphertext = encrypted_data[16:]
    
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

    if "***" in decrypted_data:
        message, received_hash, _ = decrypted_data.split("***")

        print(f"\n[Server] Received (After Decryption): {message} | Hash: {received_hash}")

        
        expected_hash = compute_hash(message)
        if received_hash == expected_hash:
            print("[Server] Integrity Check ")
            return message
        else:
            print("[Server] Integrity Check ")
            return None
    else:
        print("[Server] Invalid message format ")
        return None


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", 12345))
server_socket.listen(1)
print("[Server] Waiting for a client...")

conn, addr = server_socket.accept()
print(f"[Server] Connected to {addr}")


private_key_B, public_key_B, p, g = generate_dh_keys()
conn.send(f"{public_key_B},{p},{g}".encode())  # Send public key, p, g

public_key_A = int(conn.recv(1024).decode())  # Receive client's public key
session_key = derive_shared_key(private_key_B, public_key_A, p)
print("[Server] Shared AES Key Established ")


while True:
    encrypted_data = conn.recv(4096)
    if not encrypted_data:
        break

    decrypted_message = decrypt_message(session_key, encrypted_data)
    
    
    reply = input("[Server] Enter reply: ")
    encrypted_reply = encrypt_message(session_key, reply)
    print(f"[Server] Sent (Encrypted): {encrypted_reply.hex()}")
    conn.send(encrypted_reply)

print("[Server] Connection closed.")
conn.close()
server_socket.close()
