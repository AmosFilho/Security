import socket
import threading
import random

def generate_key():
    key = random.randint(1, 50)
    return key

def diffie_hellman(conn):
    # Gerar números aleatórios g e p para serem usados no protocolo
    g = random.randint(2, 10)
    p = random.randint(2**10, 2**20)

    # Enviar g e p para o servidor
    conn.sendall(f"{g}:{p}".encode())

    # Receber o número público do servidor
    B = int(conn.recv(1024).decode())

    # Gerar a chave compartilhada
    a = random.randint(2, p-2)
    A = pow(g, a, p)
    conn.sendall(str(A).encode())
    key = pow(B, a, p)

    return key


def rc4(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    ciphertext = []
    for c in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        ciphertext.append(chr(ord(c) ^ k))
    return ''.join(ciphertext)


def send_message(conn, key, nonce):
    while True:
        plaintext = input()
        if not plaintext:
            continue
        ciphertext = rc4(plaintext, str(key))
        conn.sendall(f"{nonce}:{ciphertext}".encode())

def receive_message(conn, key):
    while True:
        data = conn.recv(1024).decode()
        nonce, ciphertext = data.split(":")
        plaintext = rc4(ciphertext, key)
        print(f"{nonce}: {plaintext}")





def start_client():
    host = '127.0.0.1'
    port = 12345

    client_id = generate_key()

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host, port))
    conn.sendall(str(client_id).encode())

    key = str(diffie_hellman(conn))
    nonce = generate_key()

    threading.Thread(target=send_message, args=(conn, key, nonce)).start()
    threading.Thread(target=receive_message, args=(conn, key)).start()

if __name__ == "__main__":
    start_client()
