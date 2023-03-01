import socket
import threading

from Crypto.Cipher import ARC4

# gerar uma chave aleatória para o RC4
key = b"my secret key"

public_partner = None


choice = input("Do you want to host (1) or to connect(2)?")

if choice == "1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("192.168.0.7", 9998))
    server.listen()

    client, _ = server.accept()
    client.send(key)
    public_partner = client.recv(1024)
elif choice == "2":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("192.168.0.7", 9998))
    public_partner = client.recv(1024)
    client.send(key)
else:
    exit()

# criar um objeto de cifra RC4 com a chave gerada
rc4_cipher = ARC4.new(key)

def sending_messages(c):
    while True:
        message = input("")
        # cifrar a mensagem usando o RC4
        ciphertext = rc4_cipher.encrypt(message.encode())
        c.send(ciphertext)
        print("You: "+ message)

def receiving_messages(c):
    while True:
        # receber o texto cifrado
        ciphertext = c.recv(1024)
        # decifrar o texto cifrado usando o RC4
        plaintext = rc4_cipher.decrypt(ciphertext).decode()
        print("Partner: " + plaintext)


threading.Thread(target=sending_messages, args=(client, )).start()
threading.Thread(target=receiving_messages, args=(client, )).start()
