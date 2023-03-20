import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from df import DiffieHellman
class ChatClient:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.connect()
        while True:
            message = input("> ")
            if message.lower() == "exit":
                break
            self.send_message(message)

        self.client.close()

    def connect(self):
        self.client.connect((self.host, self.port))
        self.dh = DiffieHellman()
        message = self.client.recv(1024).decode('utf-8')
        if ':' not in message:
            raise ValueError("Received message does not have expected format")
        server_public_key = int(message.split(': ')[1])
        self.client.send(f"Public key: {str(self.dh.public_key)}".encode('utf-8'))
        self.shared_secret = self.dh.generate_shared_secret(server_public_key)
        salt = self.shared_secret.to_bytes((self.shared_secret.bit_length() + 7) // 8, 'big')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        self.key = kdf.derive(b"my secret key")
        self.fernet = Fernet(self.key)

    def send_message(self, message):
        ciphertext = self.fernet.encrypt(message.encode('utf-8'))
        self.client.send(ciphertext)

    def receive_message(self):
        ciphertext = self.client.recv(4096)
        if not ciphertext:
            return None
        message = self.fernet.decrypt(ciphertext).decode('utf-8')
        return message

if __name__ == '__main__':
    client = ChatClient()
    client.start()
