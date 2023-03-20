import socket
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from df import DiffieHellman

class ChatServer:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []

    def start(self):
        self.server.bind((self.host, self.port))
        self.server.listen()

        while True:
            client_socket, address = self.server.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
            client_thread.start()

    def handle_client(self, client_socket, address):
        try:
            client = ChatClientHandler(client_socket, address)
            client.connect()
            self.broadcast(f"User {address[0]}:{address[1]} joined the chat.")
            self.clients.append(client)

            while True:
                message = client.receive_message()
                if not message:
                    break
                self.broadcast(f"User {address[0]}:{address[1]}: {message}")

            client_socket.close()
            self.clients.remove(client)
            self.broadcast(f"User {address[0]}:{address[1]} left the chat.")
        except Exception as e:
            print(f"Error: {e}")

    def broadcast(self, message):
        for client in self.clients:
            client.send_message(message)

class ChatClientHandler:
    def __init__(self, client_socket, address):
        self.client_socket = client_socket
        self.address = address

    def connect(self):
        self.dh = DiffieHellman()
        self.client_socket.send(f"Public key: {str(self.dh.public_key)}".encode('utf-8'))
        message = self.client_socket.recv(1024).decode('utf-8')
        if ':' not in message:
            raise ValueError("Received message does not have expected format")
        server_public_key = int(message.split(': ')[1])
        self.shared_secret = self.dh.generate_shared_secret(server_public_key)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.shared_secret,
            iterations=100000,
        )
        self.key = kdf.derive(b"my secret key")
        self.fernet = Fernet(self.key)

    def send_message(self, message):
        ciphertext = self.fernet.encrypt(message.encode('utf-8'))
        self.client_socket.send(ciphertext)

    def receive_message(self):
        ciphertext = self.client_socket.recv(4096)
        if not ciphertext:
            return None
        message = self.fernet.decrypt(ciphertext).decode('utf-8')
        return message

if __name__ == '__main__':
    server = ChatServer()
    server.start()
