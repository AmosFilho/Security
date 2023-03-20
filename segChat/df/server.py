import socket
import threading
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from df import DiffieHellman

class ChatServer:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []
        print(self.port, self.host)


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
        self.client_socket.send(f"Public key: {self.dh.public_key}".encode('utf-8'))
        client_public_key = int(self.client_socket.recv(1024).decode('utf-8').split(': ')[1])
        self.shared_secret = self.dh.generate_shared_secret(client_public_key)
        self.aes_key = self.derive_key(self.shared_secret, b"random_salt")

    def send_message(self, message):
        cipher = AES.new(self.aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        self.client_socket.send(cipher.nonce + tag + ciphertext)

    def receive_message(self):
        data = self.client_socket.recv(4096)
        if not data:
            return None

        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]

        cipher = AES.new(self.aes_key, AES.MODE_EAX, nonce)
        message = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        return message

    def derive_key(self, master_key, salt):
        derived_key = b""
        hash_size = hashlib.sha256().digest_size
        iterations = (len(master_key.to_bytes((master_key.bit_length() + 7) // 8, 'big')) + hash_size - 1) // hash_size
        for i in range(iterations):
            hmac_obj = hmac.new(master_key.to_bytes((master_key.bit_length() + 7) // 8, 'big'), salt + bytes([i]), hashlib.sha256)
            derived_key += hmac_obj.digest()
        print(derived_key)
        return derived_key[:32]

if __name__ == '__main__':
    server = ChatServer()
    server.start()
