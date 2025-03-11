import socket
import random

# Diffie-Hellman parameters
p = 23  
g = 5

# Generate private and public keys
client_private = random.randint(2, p-2)
client_public = pow(g, client_private, p)

# Connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Exchange public keys
client_socket.send(str(client_public).encode())
server_public = int(client_socket.recv(1024).decode())

# Compute shared key
shared_key = pow(server_public, client_private, p)
shift = shared_key % 26  

print(f"Shared Key: {shared_key}, Shift: {shift}")

# Caesar Cipher Functions
def caesar_encrypt(text, shift):
    return ''.join(chr((ord(char) - ord('A') + shift) % 26 + ord('A')) if char.isalpha() else char for char in text.upper())

def caesar_decrypt(text, shift):
    return ''.join(chr((ord(char) - ord('A') - shift) % 26 + ord('A')) if char.isalpha() else char for char in text.upper())

while True:
    # Get user input
    message = input("\nYou: ")

    # Encrypt message
    encrypted_message = caesar_encrypt(message, shift)
    
    # Send encrypted message
    print(f"Sending Encrypted Message: {encrypted_message}")
    client_socket.sendall(encrypted_message.encode())

    # Receive encrypted response
    encrypted_response = client_socket.recv(1024).decode()
    if not encrypted_response:
        break

    print(f"Received Encrypted Response: {encrypted_response}")

    # Decrypt response
    decrypted_response = caesar_decrypt(encrypted_response, shift)
    
    print(f"Decrypted Server Response: {decrypted_response}")

client_socket.close()
