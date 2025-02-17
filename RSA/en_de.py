# Modular exponentiation (for encryption and decryption)
def mod_exponent(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

# Encrypt message (convert characters to numbers)
def encrypt_message(message, public_key):
    e, n = public_key
    return [mod_exponent(ord(char), e, n) for char in message]

# Decrypt message (convert numbers back to characters)
def decrypt_message(encrypted_message, private_key):
    d, n = private_key
    return ''.join(chr(mod_exponent(num, d, n)) for num in encrypted_message)
