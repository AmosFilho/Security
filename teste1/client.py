import socket
import threading
import random

def generate_key():
    key = random.randint(1, 50)
    return key

def send_message(conn):
    while True:
        msg = input()
        conn.sendall(msg.encode())

def receive_message(conn):
    while True:
        msg = conn.recv(1024).decode()
        print(msg)

def start_client():
    host = '127.0.0.1'
    port = 12345

    client_id = generate_key()

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host, port))
    conn.sendall(str(client_id).encode())

    threading.Thread(target=send_message, args=(conn,)).start()
    threading.Thread(target=receive_message, args=(conn,)).start()

if __name__ == "__main__":
    start_client()
