import socket
from Crypto.PublicKey import DH
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
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    # Gerar parâmetros e chave Diffie-Hellman
    dh = DH.generate(2048)
    client_public_key = dh.public_key()

    # Enviar a chave pública do cliente para o servidor
    client.sendall(client_public_key.to_bytes())

    # Receber a chave pública do servidor
    server_public_key_bytes = client.recv(256)
    server_public_key = int.from_bytes(server_public_key_bytes, 'big')

    # Calcular a chave compartilhada
    shared_key = dh.exchange(server_public_key)

    # Gerar uma chave AES e um nonce
    aes_key = shared_key[:32]
    aes_nonce = get_random_bytes(16)

    while True:
        client_message = input("Cliente: ")
        encrypted_message = encrypt_message(client_message.encode(), aes_key, aes_nonce)
        client.sendall(encrypted_message)

        data = client.recv(1024)
        if not data:
            break

        decrypted_message = decrypt_message(data, aes_key, aes_nonce)
        print(f"Servidor: {decrypted_message.decode()}")

    client.close()

if __name__ == '__main__':
    main()
