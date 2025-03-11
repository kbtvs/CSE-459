import math


def modInverse(b,m):
    g = math.gcd(b, m) 
    if (g != 1):
        print("Inverse doesn't exist") 
        return -1
    else:  
        return pow(b, -1, m)

def modDivide(a,b,m):
    a = a % m
    inv = modInverse(b,m)
    if(inv == -1):
        print("Division not defined")
    else:
        print("Result of Division is ",(inv*a) % m)



a=int(input("a="))
b=int(input("b="))
m=int(input("m="))
print("Modular Dision of a,b with m=",m) 
k=modDivide(a, b, m)
