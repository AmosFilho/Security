import random

class DiffieHellman:
    def __init__(self, p=2147483647, g=5):
        self.p = p
        self.g = g
        self.private_key = random.randint(1, self.p - 1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def generate_shared_secret(self, other_public_key):
        return pow(other_public_key, self.private_key, self.p)
