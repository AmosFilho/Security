import socket
import threading
import random

def generate_key():
    key = random.randint(1, 50)
    return key

def client_handler(conn, addr, clients):
    client_id = conn.recv(1024).decode()
    clients[client_id] = conn
    print(f"{client_id} acabou de se conectar")
    while True:
        try:
            data = conn.recv(1024).decode()
            if not data:
                break
            for id, client in clients.items():
                if id != client_id:
                    client.sendall(f"{client_id}: {data}".encode())
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
