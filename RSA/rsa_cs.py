import socket
from en_de import encrypt_message, decrypt_message  # RSA functions

# Create client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 12345))

# Receive the public key from the server
public_key = eval(client_socket.recv(1024).decode())  # Convert string to tuple
print(f"Received Server Public Key: {public_key}")

while True:
    # Get user input
    message = input("\nYou: ")

    # Encrypt message
    encrypted_message = encrypt_message(message, public_key)
    encrypted_str = ','.join(map(str, encrypted_message))
    
    # Send encrypted message
    print(f"Sending Encrypted Message: {encrypted_str}")
    client_socket.sendall(encrypted_str.encode())

    # Receive encrypted response
    encrypted_response = client_socket.recv(1024).decode()
    if not encrypted_response:
        break

    print(f"Received Encrypted Response: {encrypted_response}")

    # Decrypt response
    encrypted_list = list(map(int, encrypted_response.split(',')))
    decrypted_response = decrypt_message(encrypted_list, public_key)
    
    print(f"Decrypted Server Response: {decrypted_response}")

client_socket.close()
