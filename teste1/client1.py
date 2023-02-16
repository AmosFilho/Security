import socket
import threading
from Crypto.Cipher import ARC4
from Crypto.Util.number import getPrime, getRandomRange

host = 'localhost'
port = 5555
# Gera um número primo aleatório com até 25 dígitos
def generate_prime():
    return getPrime(25)

# Gera um valor aleatório para o Diffie-Hellman
def generate_dh_value():
    return getRandomRange(2, generate_prime())

# Implementa o protocolo de Diffie-Hellman
def diffie_hellman(conn):
    # Gera o valor secreto do cliente
    client_secret = generate_dh_value()
    
    # Calcula o valor público do cliente
    client_public = pow(5, client_secret, generate_prime())
    
    # Envia o valor público do cliente para o servidor
    conn.send(str(client_public).encode("ISO-8859-1"))
    
    # Recebe o valor público do servidor
    server_public = int(conn.recv(1024).decode("ISO-8859-1"))
    
    # Calcula a chave de sessão
    session_key = pow(server_public, client_secret, generate_prime())
    
    return session_key

# Função para receber mensagens do servidor
def receive_loop(conn, cipher):
    while True:
        # Recebe a mensagem cifrada do servidor
        ciphertext = conn.recv(1024)
        if not ciphertext:
            break
        
        # Decifra a mensagem com o objeto de criptografia RC4
        plaintext = cipher.decrypt(ciphertext).decode("ISO-8859-1")
        
        print(plaintext)

# Função para enviar mensagens para o servidor
def send_loop(conn, cipher, client_name):
    while True:
        # Lê uma mensagem do usuário
        message = input(f"{client_name}: ")
        
        # Cifra a mensagem com o objeto de criptografia RC4
        ciphertext = cipher.encrypt(message.encode("ISO-8859-1"))
        
        # Envia a mensagem cifrada para o servidor
        conn.send(ciphertext)
        
        if message == "exit":
            break

# Função principal do cliente
def main():
        # Criando o socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Conectando ao servidor
    client_socket.connect((host, port))
    print("Conectado ao servidor.")

    # Enviando nome do cliente ao servidor
    client_name = input("Digite seu nome: ")
    client_socket.send(client_name.encode("ISO-8859-1"))

    # Iniciando Diffie-Hellman e obtendo chave de sessão
    session_key = diffie_hellman(client_socket)

    # Iniciando thread para receber mensagens do servidor
    receive_thread = threading.Thread(target=receive_loop, args=(client_socket,))
    receive_thread.start()

    # Loop principal do cliente
    while True:
        # Lendo mensagem do usuário
        message = input("Digite sua mensagem: ")

        # Encriptando e enviando mensagem ao servidor
        cipher = ARC4.new(session_key)
        ciphertext = cipher.encrypt(message.encode("ISO-8859-1"))
        client_socket.send(ciphertext)

        # Aguardando confirmação de recebimento do servidor
        received = client_socket.recv(1024)
        if received != b'ACK':
            print("Erro ao enviar mensagem.")
        
        # Inicia as threads de recepção e envio de mensagens
        receive_thread = threading.Thread(target=receive_loop, args=(client_socket, cipher))
        send_thread = threading.Thread(target=send_loop, args=(client_socket, cipher, client_name))
        receive_thread.start()
        send_thread.start()

if __name__ == "__main__":
    main()