import socket

HOST = 'localhost'  # Endereço IP do servidor
PORT = 5000  # Porta em que o servidor está escutando

def main():
    username = input('Digite seu nome de usuário: ')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.send(username.encode())
        while True:
            message = input('> ')
            s.send(message.encode())

if __name__ == "__main__":
    main()