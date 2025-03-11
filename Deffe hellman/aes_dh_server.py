import socket
import random

# Diffie-Hellman parameters
p = 23  
g = 5

# Generate private and public keys
server_private = random.randint(2, p-2)
server_public = pow(g, server_private, p)

# Set up server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)

print("Server is waiting for connection...")
conn, addr = server_socket.accept()
print(f"Connected to {addr}")

# Exchange public keys
client_public = int(conn.recv(1024).decode())
conn.send(str(server_public).encode())

# Compute shared key
shared_key = pow(client_public, server_private, p)
shift = shared_key % 26  

print(f"Shared Key: {shared_key}, Shift: {shift}")

# Caesar Cipher Functions
def caesar_encrypt(text, shift):
    return ''.join(chr((ord(char) - ord('A') + shift) % 26 + ord('A')) if char.isalpha() else char for char in text.upper())

def caesar_decrypt(text, shift):
    return ''.join(chr((ord(char) - ord('A') - shift) % 26 + ord('A')) if char.isalpha() else char for char in text.upper())

while True:
    # Receive encrypted message
    encrypted_data = conn.recv(1024).decode()
    if not encrypted_data:
        break

    print(f"\nReceived Encrypted Message: {encrypted_data}")

    # Decrypt message
    decrypted_data = caesar_decrypt(encrypted_data, shift)
    print(f"Decrypted Message: {decrypted_data}")

    # Get server response
    message = input("\nYou: ")
    
    # Encrypt response
    encrypted_response = caesar_encrypt(message, shift)

    # Send encrypted response
    print(f"Sending Encrypted Message: {encrypted_response}")
    conn.sendall(encrypted_response.encode())

conn.close()
server_socket.close()
