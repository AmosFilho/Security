import socket
import threading
from cryptography.fernet import Fernet
from Crypto.Random import random
from Crypto.Util.Padding import pad
import base64
import hashlib
import pickle


shared_key = None
key_lock = threading.Lock()


clients = []

# Diffie-Hellman parameters
prime = int("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63", 16)

generator = 2

def handle_client(client, addr):
    global shared_key, key_lock
    ...

    print(f"[CONNECTION] {addr} connected.")
    clients.append(client)

    # Diffie-Hellman key exchange
    dh_private_key = random.getrandbits(256)
    dh_public_key = pow(generator, dh_private_key, prime)
    client.sendall(str(dh_public_key).encode())
    client_public_key = int(client.recv(1024).decode())
    with key_lock:
        if shared_key is None:
            shared_key = pow(client_public_key, dh_private_key, prime)
    key_material = hashlib.sha256(str(shared_key).encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_material)
    fernet = Fernet(fernet_key)
    print(f"Shared key: {shared_key}")

    shared_key_bytes = hashlib.sha256(str(shared_key).encode()).digest()
    fernet = Fernet(base64.urlsafe_b64encode(shared_key_bytes))


    while True:
        try:
            encrypted_msg = client.recv(1024)
            if not encrypted_msg:
                break
            broadcast(encrypted_msg, client, fernet)
        except Exception as e:
            print(f"[ERROR] {e}")
            break
            

    clients.remove(client)
    print(f"[DISCONNECTED] {addr} disconnected.")
    client.close()

def broadcast(encrypted_msg, sender, fernet):
    for client in clients:
        if client != sender:
            try:
                ip = sender.getpeername()[0]
                decrypted_msg = fernet.decrypt(encrypted_msg)
                ip_msg = (ip, decrypted_msg.decode("utf-8"))
                serialized_ip_msg = pickle.dumps(ip_msg)
                encrypted_ip_msg = fernet.encrypt(serialized_ip_msg)
                client.send(encrypted_ip_msg)
                

            except:
                print(f"[ERROR] Failed to send message to {client}")

def start_server(server):
    server.listen()
    print(f"[LISTENING] Server is listening on {IP}:{PORT}")
    while True:
        client, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client, addr))
        thread.start()
        

if __name__ == "__main__":
    IP = "127.0.0.1"
    PORT = 12345
    ADDR = (IP, PORT)
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)

    start_server(server)
