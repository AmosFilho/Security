from socket import socket, AF_INET, SOCK_STREAM
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from Crypto.Cipher import ARC4

def generate_dh_keypair(p):
    g = 2
    a = getPrime(16)
    A = pow(g, a, p)
    return (A, a)

def generate_shared_secret(A, a, p):
    return pow(A, a, p)

def rc4_encrypt(key, data):
    cipher = ARC4.new(key)
    return cipher.encrypt(data)

def rc4_decrypt(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def start_client():
    client = socket(AF_INET, SOCK_STREAM)
    client.connect(('localhost', 8080))

    p = bytes_to_long(client.recv(1024))
    dh_public_key, dh_private_key = generate_dh_keypair(p)
    client.send(long_to_bytes(dh_public_key))
    shared_secret = generate_shared_secret(bytes_to_long(client.recv(1024)), dh_private_key, p)
    key = long_to_bytes(shared_secret)

    while True:
        message = input("Enter message: ")
        client.send(rc4_encrypt(key, message.encode(('latin-1'))))


if __name__ == '__main__':
    start_client()
