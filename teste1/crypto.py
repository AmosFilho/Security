import secrets
from sympy import isprime


class RC4:
    def __init__(self, key):
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def crypt(self, plaintext):
        ciphertext = bytearray()
        for b in plaintext:
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            k = self.S[(self.S[self.i] + self.S[self.j]) % 256]
            ciphertext.append(b ^ k)
        return bytes(ciphertext)


class DiffieHellman:
    def __init__(self, p=None, g=None):
        self.p = p or self.generate_prime()
        self.g = g or self.primitive_root(self.p)
        self.secret = secrets.randbits(128)
        self.public_key = pow(self.g, self.secret, self.p)

    def generate_prime(self):
        while True:
            p = secrets.randbits(1024)
            if isprime(p):
                return p

    def primitive_root(self, p):
        factors = [1, p - 1]
        for i in range(2, p - 1):
            if (p - 1) % i == 0:
                factors.append(i)
        for g in range(2, p):
            if all(pow(g, (p - 1) // f, p) != 1 for f in factors):
                return g

    def generate_shared_secret(self, public_key):
        return pow(public_key, self.secret, self.p)
