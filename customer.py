from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib

rsa_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


class Customer:
    def __init__(self):
        self.__rsa_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.public_key = self.__rsa_key.public_key()

    def sign(self, PI, OI):
        PIMD = hashlib.sha256(PI.encode()).hexdigest()
        OIMD = hashlib.sha256(OI.encode()).hexdigest()

        POMD = hashlib.sha256((PIMD + OIMD).encode()).hexdigest()
        signed_POMD = self.__rsa_key.sign(POMD.encode(),rsa_padding,hashes.SHA256())
        return signed_POMD, PIMD, OIMD
