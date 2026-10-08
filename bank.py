from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib

rsa_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


class Bank:
    def __init__(self, public_key):
        self.rsa_pubkey = public_key

    def bankVerify(self, signed_POMD, PI, OIMD):
        bank_pimd = hashlib.sha256(PI.encode()).hexdigest()
        combined_hash = bank_pimd + OIMD
        cal_pomd = hashlib.sha256(combined_hash.encode()).hexdigest()
        return self.rsa_pubkey.verify(signed_POMD,cal_pomd.encode() , rsa_padding, hashes.SHA256())
