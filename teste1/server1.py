import socket
import threading
import random

def generate_key():
    key = random.randint(1, 50)
    return key

def rc4(key, data):
    S = list(range(256))
    j = 0
    out = []
    # KSA (Key Scheduling Algorithm)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA (Pseudo Random Generation Algorithm)
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(ord(char) ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def client_handler(conn, addr, clients):
    client_id = conn.recv(1024).decode()
    clients[client_id] = conn
    print(f"{client_id} acabou de se conectar")
    
    # Diffie-Hellman
    p = 23
    g = 5
    a = random.randint(1, 10)
    A = (g**a) % p
    conn.sendall(str(A).encode())
    B = int(conn.recv(1024).decode())
    key = (B**a) % p
    
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            for id, client in clients.items():
                if id != client_id:
                    encrypted_data = rc4(str(key).encode(), data)
                    client.sendall(f"{client_id}: {encrypted_data.decode()}".encode())
        except ConnectionResetError:
            break
    conn.close()
    del clients[client_id]
    print(f"{client_id} desconectado")

def start_server():
    host = '127.0.0.1'
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen()

    clients = {}
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=client_handler, args=(conn, addr, clients)).start()

if __name__ == "__main__":
    start_server()
