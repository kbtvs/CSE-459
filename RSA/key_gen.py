import random

# Function to check if a number is prime (Basic primality test)
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

# Generate a random prime number of 'bits' size
def generate_prime(bits):
    while True:
        num = random.randint(2**(bits - 1), 2**bits - 1)
        if is_prime(num):
            return num

# Compute Greatest Common Divisor (GCD)
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Compute Modular Inverse using Extended Euclidean Algorithm
def mod_inverse(e, phi):
    d=pow(e,-1,phi)
    return d

# Generate RSA Keys (public and private keys)
def generate_rsa_keys(bits=16):  # You can change bit size
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose 'e' such that 1 < e < phi and gcd(e, phi) = 1
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    # Compute 'd' (modular inverse of e)
    d = mod_inverse(e, phi)

    return (e, n), (d, n)  # Public and Private Keys
