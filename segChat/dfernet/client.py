import socket
import threading
from cryptography.fernet import Fernet
from Crypto.Random import random
from Crypto.Util.Padding import pad
import base64
import hashlib
import pickle



# Diffie-Hellman parameters
prime = int("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63", 16)

generator = 2

def receive_messages(client, fernet):
    while True:
        try:
            encrypted_msg = client.recv(1024)
            if not encrypted_msg:
                break

            serialized_ip_msg = fernet.decrypt(encrypted_msg)
            ip, msg = pickle.loads(serialized_ip_msg)
            print(f"[{ip}] {msg}")
        except Exception as e:
            print(f"Error: {e}")
            print(f"Encrypted message: {encrypted_msg}")
            

def send_messages(client, fernet):
    while True:
        msg = input()
        encrypted_msg = fernet.encrypt(msg.encode("utf-8"))
        client.send(encrypted_msg)

if __name__ == "__main__":
    IP = "127.0.0.1"
    PORT = 12345
    ADDR = (IP, PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)

    # Diffie-Hellman key exchange
    dh_private_key = random.getrandbits(256)
    server_public_key = int(client.recv(1024).decode())
    client.sendall(str(pow(generator, dh_private_key, prime)).encode())
    shared_key = pow(server_public_key, dh_private_key, prime)
    key_material = hashlib.sha256(str(shared_key).encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_material)
    fernet = Fernet(fernet_key)


    receive_thread = threading.Thread(target=receive_messages, args=(client, fernet))
    receive_thread.start()

    send_thread = threading.Thread(target=send_messages, args=(client, fernet))
    send_thread.start()
    print(f"Shared key: {shared_key}")

