import pickle
import socket
import secrets
from threading import Thread
import time
import chilkat2
import random
import string

HEADER = 4096
PORT = 5050
SERVER = "192.168.1.9"
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
ADDR = (SERVER, PORT)


def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]


crypt = chilkat2.Crypt2()
crypt.HashAlgorithm = "SHA256"
crypt.CryptAlgorithm = "twofish"
crypt.CipherMode = "cdc"
crypt.KeyLength = 256
crypt.PaddingScheme = 0
crypt.EncodingMode = "hex"
ivHex = "000102030405060708090A0B0C0D0E0F"
crypt.SetEncodedIV(ivHex, "hex")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Connecting to server...')
client.connect(ADDR)
server_key = ''

print('Receiving server data...')
received_message = client.recv(HEADER)
server_public_key_message = client.recv(HEADER)

'Creating ECDH shared key'
curve = pickle.loads(received_message)
server_public_key = pickle.loads(server_public_key_message)
print("ECDH server public key: " + str(server_public_key.x), end="\n\n")
priv_key = secrets.randbelow(curve.field.n)
pub_key = priv_key * curve.g
print("ECDH client public key: " + str(pub_key.x), end="\n\n")
shared_key = priv_key * server_public_key
secretkey = crypt.HashStringENC(str(shared_key.x))
print("ECDH shared key (S): " + secretkey, end="\n\n")

print('Sending client data')
pub_key_string = pickle.dumps(pub_key)
time.sleep(1)
client.send(pub_key_string)

print('Establishing secure connection with server...')
server_key_encrypted = client.recv(HEADER).decode(FORMAT)
crypt.SetEncodedKey((secretkey), 'hex')

'Receiving twofish key'
server_key = crypt.DecryptStringENC(server_key_encrypted)
print("server key (T): " + server_key, end="\n\n")
crypt.SetEncodedKey(server_key, 'hex')


def send(msg):
    message = crypt.EncryptStringENC(msg)
    client.send(message.encode(FORMAT))


while True:
    msg = ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(5,15)))
    send(msg)
    time.sleep(1)
