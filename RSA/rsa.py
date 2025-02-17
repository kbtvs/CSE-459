import random
import sympy

def generate_prime(bits):
    lower_bound = 2**(bits - 1)  # Smallest number with 'bits' bits
    upper_bound = 2**bits - 1    # Largest number with 'bits' bits
    return sympy.randprime(lower_bound, upper_bound)
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    d=pow(e,-1,phi)
    return d

def generate_rsa_keys():
    p = generate_prime(8)
    q = generate_prime(8)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = mod_inverse(e, phi)
    return (e, n), (d, n) 


def encrypt(message, key):
    e, n = key
    return [pow(ord(char), e, n) for char in message]


def decrypt(ciphertext, key):
    d, n = key
    return ''.join([chr(pow(char, d, n)) for char in ciphertext])


public_key, private_key = generate_rsa_keys()
message = input()

ciphertext = encrypt(message, public_key)
print("Encrypted:", ciphertext)


decrypted_message = decrypt(ciphertext, private_key)
print("Decrypted:", decrypted_message)
