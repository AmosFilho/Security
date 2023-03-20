import random
import hashlib
import sys
import gmpy2
import base64

# Função de criptografia ElGamal
def encrypt_elgamal(plaintext, p, g, y):
    # Codificação da mensagem como número
    plaintext_bytes = plaintext.encode('utf-8')
    plaintext_number = int.from_bytes(plaintext_bytes, 'big')
    # Escolha do número aleatório k
    k = random.randint(1, p - 1)
    # Cálculo de c1 e c2
    c1 = gmpy2.powmod(g, k, p)
    c2 = (plaintext_number * gmpy2.powmod(y, k, p)) % p
    return (c1, c2)


# Função de cálculo de exponenciação modular
def modexp(base, exponent, modulus):
    result = 1
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus
    return result

# Função de geração de chave pública ElGamal
def generate_elgamal_key(p, g):
    # Escolha da chave privada
    x = random.randint(1, p - 1)
    # Cálculo da chave pública
    y = modexp(g, x, p)
    return (x, y)

# Função de decriptografia ElGamal
def decrypt_elgamal(ciphertext, p, x):
    c1, c2 = ciphertext
    # Cálculo de m
    m = (c2 * modexp(c1, p - 1 - x, p)) % p
    return m

# Função de geração de chave compartilhada Diffie-Hellman
def generate_diffie_hellman_key(p, g, y):
    # Escolha da chave privada
    x = random.randint(1, p - 1)
    # Cálculo da chave compartilhada
    shared_key = modexp(y, x, p)
    return shared_key

# Função de conversão de mensagem para bytes
def message_to_bytes(message):
    return message.encode('utf-8')

# Função de conversão de bytes para mensagem
def bytes_to_message(bytes_message):
    return bytes_message.decode('utf-8')

# Função para hash SHA-256
def sha256(message):
    return hashlib.sha256(message).hexdigest()

# Função de autenticação da mensagem
def authenticate_message(message, shared_key):
    message_bytes = message_to_bytes(message)
    message_hash = sha256(message_bytes)
    shared_key_bytes = message_to_bytes(str(shared_key))
    authentication_hash = sha256(message_hash.encode('utf-8') + shared_key_bytes)
    combined_hash = sha256(message_hash.encode('utf-8') + shared_key_bytes)
    return combined_hash

# Função para verificação da autenticidade da mensagem
def verify_message(message, shared_key, received_hash):
    message_hex = hex(message)[2:]
    message_bytes = bytes.fromhex(message_hex)
    message_b64 = base64.b64encode(message_bytes).decode('utf-8')
    calculated_hash = authenticate_message(message_b64, shared_key)
    return calculated_hash == received_hash


# Função para o envio da mensagem
def send_message(message, p, g, receiver_public_key, sender_private_key, shared_key):
    # Criptografia da mensagem com ElGamal
    encrypted_message = encrypt_elgamal(message, p, g, receiver_public_key)
    # Autenticação da mensagem com a chave compartilhada
    authentication_hash = authenticate_message(message, shared_key)
    # Envio da mensagem criptografada e da autenticação
    return encrypted_message, authentication_hash

# Função para a recepção da mensagem
def receive_message(encrypted_message, p, receiver_private_key, sender_public_key, shared_key, received_hash):
    # Decriptografia da mensagem com ElGamal
    decrypted_message = decrypt_elgamal(encrypted_message, p, receiver_private_key)
    # Verificação da autenticidade da mensagem
    message_authenticated = verify_message(decrypted_message, shared_key, received_hash)
    if message_authenticated:
        return decrypted_message
    else:
        return "A mensagem não foi autenticada."

# Geração de chaves para o remetente
p = random.randint(10**20, 10**21)
g = random.randint(2, p - 1)
sender_private_key, sender_public_key = generate_elgamal_key(p, g)

# Geração de chaves para o destinatário
receiver_private_key, receiver_public_key = generate_elgamal_key(p, g)

# Geração da chave compartilhada entre o remetente e o destinatário
sender_shared_key = generate_diffie_hellman_key(p, g, receiver_public_key)
receiver_shared_key = generate_diffie_hellman_key(p, g, sender_public_key)

# Mensagem a ser enviada
message = "Olá, como você está?"

# Envio da mensagem
encrypted_message, authentication_hash = send_message(message, p, g, receiver_public_key, sender_private_key, sender_shared_key)

# Recepção da mensagem
received_message = receive_message(encrypted_message, p, receiver_private_key, sender_public_key, receiver_shared_key, authentication_hash)

# Impressão da mensagem decriptografada
print("Mensagem decriptografada:", received_message)
