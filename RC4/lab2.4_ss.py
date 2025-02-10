import socket

key=b'crypto1245783699'

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
    key = list(key)  
    S = ksa(key)  
    key_stream = prga(S, len(data))  
    return bytes([data[i] ^ key_stream[i] for i in range(len(data))])  


def receive_and_decrypt_file(host='127.0.0.1', port=12345):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print("Server is listening...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")
            encrypted_data = conn.recv(1024*1024)  

           
            with open("received_encrypted.txt", "wb") as ef:
                ef.write(encrypted_data)

            decrypted_data = rc4_encrypt_decrypt(encrypted_data, key)

            
            with open("received_decrypted.txt", "wb") as df:
                df.write(decrypted_data)

            print("Files saved: Encrypted and Decrypted.")

receive_and_decrypt_file()
