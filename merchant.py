from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib

rsa_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


class Merchant:
    def __init__(self, public_key):
        self.rsa_pubkey = public_key

    def merchantVerify(self, signed_POMD, OI, PIMD):
        merchant_oimd = hashlib.sha256(OI.encode()).hexdigest()
        combined_hash = PIMD + merchant_oimd
        cal_pomd = hashlib.sha256(combined_hash.encode()).hexdigest()
        return self.rsa_pubkey.verify(signed_POMD,cal_pomd.encode() , rsa_padding, hashes.SHA256())
