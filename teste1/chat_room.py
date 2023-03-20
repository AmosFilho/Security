from Crypto.Cipher import ARC4
import socket
import threading

# Define a key for RC4 encryption
import secrets

# Gera uma chave RC4 aleatória com 16 bytes
key = secrets.token_bytes(16)

class ChatServer:
    def __init__(self, host, port):
        # Create a new instance of ARC4 cipher with the key
        self.cipher = ARC4.new(key, encoding="latin-1")

        # Create a socket object
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to the host and port
        self.server_socket.bind((host, port))

        # Listen for incoming connections
        self.server_socket.listen()

        # Create a list to store connected clients
        self.clients = []

        print(f'Server is listening on {host}:{port}')

    def start(self):
        # Start a thread to handle incoming connections
        threading.Thread(target=self.accept_clients).start()

    def accept_clients(self):
        while True:
            # Accept a new connection
            client_socket, client_address = self.server_socket.accept()
            print(f'Connected by {client_address}')

            # Add the client to the list of connected clients
            self.clients.append(client_socket)

            # Start a new thread to handle messages from the client
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        while True:
            # Receive data from the client
            data = client_socket.recv(1024)
            if not data:
                # Remove the client from the list of connected clients
                self.clients.remove(client_socket)
                break

            # Decrypt the received data using RC4
            decrypted_data = self.cipher.decrypt(data)

            # Print the received message
            print(f'Received from {client_socket.getpeername()}: {decrypted_data.decode()}')

            # Send the message to all connected clients except the sender
            for client in self.clients:
                if client != client_socket:
                    client.sendall(data)

class ChatClient:
    def __init__(self, host, port):
        # Create a new instance of ARC4 cipher with the key
        self.cipher = ARC4.new(key)

        # Create a socket object
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the server
        self.client_socket.connect((host, port))

    def start(self):
        # Start a thread to handle incoming messages
        threading.Thread(target=self.receive_messages).start()

        # Get a message from the user and send it to the server
        while True:
            message = input('Enter a message: ')

            # Encrypt the message using RC4
            encrypted_message = self.cipher.encrypt(message.encode())

            # Send the encrypted message to the server
            self.client_socket.sendall(encrypted_message)

    def receive_messages(self):
        while True:
            # Receive data from the server
            data = self.client_socket.recv(1024)
            if not data:
                break

            # Decrypt the received data using RC4
            decrypted_data = self.cipher.decrypt(data)

            # Print the received message
            print(f'Received: {decrypted_data.decode()}')

        # Close the client socket
        self.client_socket.close()

if __name__ == '__main__':
    # Define the host and port to use for the chat room
    HOST = 'localhost'
    PORT = 5000

   
