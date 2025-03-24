import hashlib

str=input()
result = hashlib.sha512(str.encode())
#print(result)
print("Hexadecimal eq of sha512: ")
print(result.hexdigest())