import socket
import threading
from cryptography.fernet import Fernet

def receive_messages(client, fernet):
    while True:
        try:
            encrypted_msg = client.recv(1024)
            decrypted_msg = fernet.decrypt(encrypted_msg)
            ip, msg = decrypted_msg.decode("utf-8").split(" ", 1)
            print(f"[{ip}] {msg}")
        except:
            print("Connection lost")
            break

def send_messages(client, fernet):
    while True:
        msg = input()
        encrypted_msg = fernet.encrypt(msg.encode("utf-8"))
        client.send(encrypted_msg)

if __name__ == "__main__":
    IP = "127.0.0.1"
    PORT = 12345
    ADDR = (IP, PORT)
    
    # Use the same key as the server
    KEY = b'kTnRZFpNDCZxLSqgGDFKbyWHL0rOcITa-NDHZBJi1No='
    fernet = Fernet(KEY)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)

    receive_thread = threading.Thread(target=receive_messages, args=(client, fernet))
    receive_thread.start()

    send_thread = threading.Thread(target=send_messages, args=(client, fernet))
    send_thread.start()
