import socket
import threading
from Crypto.Cipher import ARC4
from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes

HOST = 'localhost'  # Endereço do servidor
PORT = 5000  # Porta do servidor
PRIME = getPrime(128)  # Número primo usado no Diffie-Hellman
GENERATOR = 2  # Gerador usado no Diffie-Hellman

class ChatRoom:
    def _init_(self):
        self.users = {}  # Dicionário que mapeia o nome do usuário para o objeto de conexão
        self.lock = threading.Lock()  # Lock para evitar condições de corrida

    def broadcast(self, sender, message):
        """
        Envia uma mensagem para todos os usuários, exceto o remetente.
        """
        encrypted_message = self.encrypt_message(sender, message)
        for username, conn in self.users.items():
            if username != sender:
                conn.send(encrypted_message)

    def handle(self, conn, addr):
        """
        Lida com uma conexão de usuário.
        """
        # Inicia o protocolo Diffie-Hellman
        conn.send(f'{PRIME},{GENERATOR}'.encode())
        client_public_key = int(conn.recv(1024).decode())
        secret = pow(client_public_key, get_random_bytes(1)[0], PRIME)

        # Recebe o nome do usuário
        username = conn.recv(1024).decode()
        print(f'{username} se conectou de {addr}')

        # Adiciona o usuário à lista de usuários
        with self.lock:
            self.users[username] = conn

        try:
            while True:
                # Recebe uma mensagem do usuário
                encrypted_message = conn.recv(1024)
                if not encrypted_message:
                    break
                message = self.decrypt_message(username, encrypted_message)
                print(f'{username}: {message}')

                # Envia a mensagem para todos os usuários
                self.broadcast(username, message)

                # Envia uma nova chave de criptografia
                conn.send(get_random_bytes(1) + secret.to_bytes(16, 'big'))
        except:
            # Remove o usuário da lista de usuários se a conexão for encerrada
            with self.lock:
                del self.users[username]
            print(f'{username} desconectou')
            self.broadcast(username, f'{username} saiu do chat.')

    def encrypt_message(self, sender, message):
        """
        Criptografa uma mensagem usando RC4 com a chave secreta compartilhada entre o remetente e o receptor.
        """
        key = self.get_secret_key(sender)
        cipher = ARC4.new(key)
        return cipher.encrypt(message.encode())

    def decrypt_message(self, receiver, encrypted_message):
        """
        Descriptografa uma mensagem usando RC4 com a chave secreta compartilhada entre o remetente e o receptor.
        """
        key = self.get_secret_key(receiver)
        cipher = ARC4.new(key)
        return cipher.decrypt(encrypted_message).decode()

    def get_secret_key(self, username):
      """
      Retorna a chave secreta compartilhada entre o usuário especificado e o remetente da última mensagem.
      """
      with self.lock:
          usernames = list(self.users.keys())
      index = usernames.index(username)
      sender = usernames[index - 1]  # Remetente da última mensagem
      secret = self.get_secret(sender, username)
      return secret.to_bytes(16, 'big')

    def get_secret(self, user1, user2):
        """
        Calcula a chave secreta compartilhada entre dois usuários usando o protocolo Diffie-Hellman.
        """
        private_key = get_random_bytes(1)[0]
        client_public_key = pow(GENERATOR, private_key, PRIME)
        self.users[user1].send(str(client_public_key).encode())
        server_public_key = int(self.users[user1].recv(1024).decode())
        secret = pow(server_public_key, private_key, PRIME)

        private_key = get_random_bytes(1)[0]
        client_public_key = pow(GENERATOR, private_key, PRIME)
        self.users[user2].send(str(client_public_key).encode())
        server_public_key = int(self.users[user2].recv(1024).decode())
        secret2 = pow(server_public_key, private_key, PRIME)

        return secret
    
    def start(self):
        """
        Inicia o servidor e espera por conexões de usuários.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            print(f'O servidor está ouvindo em {HOST}:{PORT}')
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle, args=(conn, addr)).start()

if __name__ == "__main__":
    chatroom = ChatRoom()
    chatroom.start()