from socket import socket, AF_INET, SOCK_STREAM
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from Crypto.Cipher import ARC4
import threading
clients = []

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

def handle_client(client, address, p, dh_private_key):
    print(f"[+] Accepted connection from {address[0]}:{address[1]}")
    client.send(long_to_bytes(p))

    dh_public_key = bytes_to_long(client.recv(1024))
    shared_secret = generate_shared_secret(dh_public_key, dh_private_key, p)
    key = long_to_bytes(shared_secret)

    while True:
        encrypted_data = client.recv(1024)
        if not encrypted_data:
            break
        decrypted_data = rc4_decrypt(key, encrypted_data)
        print(f"[{address[0]}:{address[1]}] {decrypted_data.decode('latin-1')}")


        for c in clients:
            if c == client:
                continue
            c.send(rc4_encrypt(key, decrypted_data))

    print(f"[-] Closed connection from {address[0]}:{address[1]}")
    client.close()

def start_server():
    server = socket(AF_INET, SOCK_STREAM)
    server.bind(('0.0.0.0', 8080))
    server.listen(5)

    print("[*] Listening on 0.0.0.0:8080")

    p = getPrime(16)
    dh_public_key, dh_private_key = generate_dh_keypair(p)

    
    while True:
        client, address = server.accept()
        clients.append(client)
        client.send(long_to_bytes(dh_public_key))
        client.recv(1024)
        handle_client_thread = threading.Thread(target=handle_client, args=(client, address, p, dh_private_key))
        handle_client_thread.start()

if __name__ == '__main__':
    start_server()
