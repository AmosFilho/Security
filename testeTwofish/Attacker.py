import pickle
import socket
import secrets
from threading import Thread
import time
import chilkat2

HEADER = 4096
PORT = 5050
SERVER = "127.0.0.1"
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
ADDR = (SERVER, PORT)

crypt = chilkat2.Crypt2()
crypt.HashAlgorithm = "SHA256"
crypt.CryptAlgorithm = "twofish"
crypt.CipherMode = "cdc"
crypt.KeyLength = 256
crypt.PaddingScheme = 0
crypt.EncodingMode = "hex"
ivHex = "000102030405060708090A0B0C0D0E0F"
crypt.SetEncodedIV(ivHex,"hex")


print('Connecting to server...')
while True:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    time.sleep(1)
    print("Sending Message to server...")
    client.connect(ADDR)
    time.sleep(1)
    client.close()

input()
