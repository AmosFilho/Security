import socket
import threading
from cryptography.fernet import Fernet

clients = []


def generate_key():
    return Fernet.generate_key()

def handle_client(client, addr, fernet):
    print(f"[CONNECTION] {addr} connected.")
    clients.append(client)

    while True:
        try:
            encrypted_msg = client.recv(1024)
            if not encrypted_msg:
                break
            broadcast(encrypted_msg, client)
        except Exception as e:
            print(f"[ERROR] {e}")
            break

    clients.remove(client)
    print(f"[DISCONNECTED] {addr} disconnected.")
    client.close()

def broadcast(encrypted_msg, sender):
    for client in clients:
        if client != sender:
            try:
                ip = sender.getpeername()[0]
                decrypted_msg = fernet.decrypt(encrypted_msg)
                ip_msg = f"{ip} {decrypted_msg.decode('utf-8')}"
                client.send(fernet.encrypt(ip_msg.encode("utf-8")))
            except:
                print(f"[ERROR] Failed to send message to {client}")


def start_server(server, fernet):
    server.listen()
    print(f"[LISTENING] Server is listening on {IP}:{PORT}")
    while True:
        client, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client, addr, fernet))
        thread.start()

if __name__ == "__main__":
    
    IP = "127.0.0.1"
    PORT = 12345
    ADDR = (IP, PORT)
    KEY = generate_key()
    fernet = Fernet(KEY)
    print(KEY)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)

    start_server(server, fernet)
    