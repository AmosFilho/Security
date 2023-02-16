import socket
import threading
from Crypto.Cipher import ARC4
from Crypto.Util.number import getPrime
from base64 import b64encode, b64decode

# Lista de conexões de clientes
client_conns = []
host = '127.0.0.1'
port = 5555
def handle_client(conn, addr):
    # Cria um novo objeto de criptografia RC4 com uma chave aleatória
    key = getPrime(25)
    cipher = ARC4.new(str(key).encode())

    # Recebe o nome do cliente
    client_name = conn.recv(1024).decode()
    print(f"[INFO] {client_name} conectado com sucesso")

    # Adiciona a conexão do cliente à lista de conexões
    client_conns.append(conn)

    try:
        while True:
            # Recebe a mensagem cifrada do cliente
            ciphertext = conn.recv(1024)
            if not ciphertext:
                break

            # Decifra a mensagem com o objeto de criptografia RC4
            plaintext = cipher.decrypt(ciphertext).decode("ISO-8859-1")

            # Adiciona o nome do cliente à mensagem recebida e a codifica em UTF-8
            message = f"[{client_name}] {plaintext}"
            encoded_message = message.encode("ISO-8859-1")

            # Cifra a mensagem com o objeto de criptografia RC4
            ciphertext = cipher.encrypt(encoded_message)

            # Envia a mensagem cifrada para todos os clientes conectados
            for client_conn in client_conns:
                client_conn.send(ciphertext)
    finally:
        # Remove a conexão do cliente da lista de conexões
        client_conns.remove(conn)
        conn.close()
        print(f"[INFO] {client_name} desconectado")

if __name__ == "__main__":
    # Criando o socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Ligando o socket a um endereço e porta
    server_socket.bind((host, port))

    # Iniciando o servidor
    server_socket.listen()
    print(f"Servidor iniciado no endereço {host}:{port}")

# Loop principal do servidor
while True:
    # Aceitando conexões de clientes
    conn, addr = server_socket.accept()
    print(f"Novo cliente conectado: {addr[0]}:{addr[1]}")

    # Criando thread para lidar com o cliente
    thread = threading.Thread(target=handle_client, args=(conn, addr))
    thread.start()

    print("[INFO] Servidor iniciado na porta 5555")

    try:
        while True:
            # Aceita uma nova conexão
            conn, addr = server_socket.accept()

            # Cria uma nova thread para lidar com o cliente
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
    finally:
        # Fecha o socket do servidor
        server_socket.close()