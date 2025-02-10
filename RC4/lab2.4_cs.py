import socket

key = b'crypto1245783699'  

def ksa(key):
    S = list(range(256))  
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i] 
    return S

def prga(S, data_length):
    i = j = 0
    key_stream = []
    for _ in range(data_length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i] 
        key_stream.append(S[(S[i] + S[j]) % 256])
    return key_stream

def rc4_encrypt_decrypt(data, key):
    key = list(key)  # Convert byte key into a list of integers
    S = ksa(key)  
    key_stream = prga(S, len(data))  
    encrypted_decrypted_data = bytes([data[i] ^ key_stream[i] for i in range(len(data))])  
    return encrypted_decrypted_data

def send_encrypted_file(filename, host='127.0.0.1', port=12345):
    with open(filename, 'rb') as f:
        data = f.read()

    encrypted_data = rc4_encrypt_decrypt(data, key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        client_socket.sendall(encrypted_data)
        print("Encrypted file sent successfully.")

send_encrypted_file('plain_text.txt')
