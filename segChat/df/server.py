import socket
from Crypto.PublicKey import DH
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def encrypt_message(message, aes_key, aes_nonce):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=aes_nonce)
    ciphertext, _ = cipher.encrypt_and_digest(message)
    return ciphertext

def decrypt_message(ciphertext, aes_key, aes_nonce):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=aes_nonce)
    message = cipher.decrypt(ciphertext)
    return message

def main():
    host = 'localhost'
    port = 12345
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    print('Servidor aguardando conexão...')
    conn, addr = server.accept()

    # Gerar parâmetros e chave Diffie-Hellman
    dh = DH.generate(2048)
    server_public_key = dh.public_key()

    # Enviar a chave pública do servidor para o cliente
    conn.sendall(server_public_key.to_bytes())

    # Receber a chave pública do cliente
    client_public_key_bytes = conn.recv(256)
    client_public_key = int.from_bytes(client_public_key_bytes, 'big')

    # Calcular a chave compartilhada
    shared_key = dh.exchange(client_public_key)

    # Gerar uma chave AES e um nonce
    aes_key = shared_key[:32]
    aes_nonce = get_random_bytes(16)

    while True:
        data = conn.recv(1024)
        if not data:
            break

        decrypted_message = decrypt_message(data, aes_key, aes_nonce)
        print(f"Cliente: {decrypted_message.decode()}")

        server_message = input("Servidor: ")
        encrypted_message = encrypt_message(server_message.encode(), aes_key, aes_nonce)
        conn.sendall(encrypted_message)

    conn.close()

if __name__ == '__main__':
    main()
