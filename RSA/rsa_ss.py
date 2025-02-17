import socket
from key_gen import generate_rsa_keys
from en_de import encrypt_message, decrypt_message  # RSA functions

# Generate RSA keys (using small keys for testing)
public_key, private_key = generate_rsa_keys(16)
print(f"Server Public Key: {public_key}")
print(f"Server Private Key: {private_key}")

# Set up server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("127.0.0.1", 12345))
server_socket.listen(1)

print("Server is waiting for a connection...")
conn, addr = server_socket.accept()
print(f"Connected to {addr}")

# Send the public key to the client
conn.sendall(str(public_key).encode())

while True:
    # Receive encrypted message
    encrypted_data = conn.recv(1024).decode()
    if not encrypted_data:
        break

    print(f"\nReceived Encrypted Message: {encrypted_data}")
    
    # Convert received encrypted string to list of integers
    encrypted_list = list(map(int, encrypted_data.split(',')))

    # Decrypt message
    decrypted_data = decrypt_message(encrypted_list, private_key)
    print(f"Decrypted Message: {decrypted_data}")

    # Get server response
    message = input("\nYou: ")
    encrypted_response = encrypt_message(message, public_key)
    encrypted_str = ','.join(map(str, encrypted_response))

    # Send encrypted response
    print(f"Sending Encrypted Message: {encrypted_str}")
    conn.sendall(encrypted_str.encode())

conn.close()
server_socket.close()
