import random
import sys
import socket
import threading

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_exp(b, e, m):
    result = 1
    while e > 0:
        if e % 2 == 1:
            result = (result * b) % m
        e = e // 2
        b = (b * b) % m
    return result

def key_exchange(p, g, a):
    A = mod_exp(g, a, p)
    B = mod_exp(g, b, p)
    s = mod_exp(B, a, p)
    return s

def rc4_encrypt(data, key):
    S = list(range(256))
    j = 0
    out = []
    for i in range(len(data)):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(data[i]) ^ S[(S[i] + S[j]) % 256]))
    return ''.join(out)

def rc4_decrypt(data, key):
    return rc4_encrypt(data, key)

def handle_server(server_socket, p, g, a):
    # Diffie-Hellman Key Exchange
    a = random.randint(1, p-1)
    A = mod_exp(g, a, p)
    server_socket.send(str(A).encode())
    B = int(server_socket.recv(4096).decode())
    s = mod_exp(B, a, p)

    # Re-geração da chave RC4
    key = str(s).encode()

    while True:
        data = input("Digite sua mensagem: ")
        encrypted_data = rc4_encrypt(data, key)
        server_socket.send(encrypted_data.encode())

        # Re-geração da chave RC4
        key = str(random.getrandbits(128)).encode()
        data = server_socket.recv(4096)
        if not data:
            break
        data = data.decode()
        decrypted_data = rc4_decrypt(data, key)
        print("Mensagem decriptografada: %s" % decrypted_data)

def start_client(host, port, p, g, a):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((host, port))
    handle_server(server_socket, p, g, a)

if __name__ == "__main__":
    p = 23
    g = 5
    a = 6
    host = "localhost"
    port = 8000
    start_client(host, port, p, g, a)