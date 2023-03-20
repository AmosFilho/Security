import socket
import threading
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from df import DiffieHellman

class ChatClient:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        self.client.connect((self.host, self.port))
        self.dh = DiffieHellman()
        self.client.send(f"Public key: {self.dh.public_key}".encode('utf-8'))
        server_public_key = int(self.client.recv(1024).decode('utf-8').split(': ')[1])
        self.shared_secret = self.dh.generate_shared_secret(server_public_key)
        self.aes_key = self.derive_key(self.shared_secret, b"random_salt")
        print(self.aes_key)
        print(self.shared_secret)

    def send_message(self, message):
        cipher = AES.new(self.aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        self.client.send(cipher.nonce + tag + ciphertext)
        print(cipher.nonce + tag + ciphertext)

    def receive_message(self):
        while True:
            try:
                data = self.client.recv(4096)
                if not data:
                    break

                nonce = data[:16]
                tag = data[16:32]
                ciphertext = data[32:]

                cipher = AES.new(self.aes_key, AES.MODE_EAX, nonce)
                message = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
                print(f"\n{message}")
            except Exception as e:
                print(f"Error: {e}")
                break

    def start(self):
        self.connect()
        thread = threading.Thread(target=self.receive_message)
        thread.start()

        while True:
            message = input("> ")
            self.send_message(message)

    def derive_key(self, master_key, salt):
        derived_key = b""
        hash_size = hashlib.sha256().digest_size
        iterations = (len(master_key.to_bytes((master_key.bit_length() + 7) // 8, 'big')) + hash_size - 1) // hash_size
        for i in range(iterations):
            hmac_obj = hmac.new(master_key.to_bytes((master_key.bit_length() + 7) // 8, 'big'), salt + bytes([i]), hashlib.sha256)
            derived_key += hmac_obj.digest()
        return derived_key[:32]

if __name__ == "__main__":
    host = input("Enter server IP: ")
    client = ChatClient(host=host)
    client.start()
