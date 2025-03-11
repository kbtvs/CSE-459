import random

def diffie_hellman(p, g):
    a = random.randint(2, p-2)
    b = random.randint(2, p-2)


    A = pow(g, a, p)
    B = pow(g, b, p)

    
    key_A = pow(B, a, p)  
    key_B = pow(A, b, p)  

    print(f"Public values: p = {p}, g = {g}")
    print(f"Alice's private key: {a}, public key: {A}")
    print(f"Bob's private key: {b}, public key: {B}")
    print(f"Shared secret key (Alice computes): {key_A}")
    print(f"Shared secret key (Bob computes): {key_B}")
    if( key_A == key_B):
        print( "Keys match!")
    else:
        print("Keys don't match!")
    return key_A


p = 23  
g = 5   
shared_key = diffie_hellman(p, g)
print("Secret Key:",shared_key)
