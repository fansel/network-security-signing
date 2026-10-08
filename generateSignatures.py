from cryptography.hazmat.primitives.asymmetric import dsa, rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import timeit


dsa_key = dsa.generate_private_key(key_size=2048)
dsa_pubkey = dsa_key.public_key()

dsa_signature = ""

rsa_key= rsa.generate_private_key(public_exponent=65537,key_size=2048)
rsa_pubkey = rsa_key.public_key()
rsa_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


rsa_signature = ""

ec_key = ec.generate_private_key(ec.SECP256R1())
ec_pubkey = ec_key.public_key()

ec_signature = ""



#DSA (Digital Signature Algorithm)
def generateDSASignatrue(toSign):
    global dsa_signature
    dsa_signature  = dsa_key.sign(toSign.encode(),hashes.SHA256())

#RSA (Rivest–Shamir–Adleman)
def generateRSASignatrue(toSign):
    global rsa_signature
    rsa_signature = rsa_key.sign(toSign.encode(),rsa_padding,hashes.SHA256())
    return rsa_signature

#ECDSA (Elliptic Curve Digital Signature Algorithm)
def generateECDSASignatrue(toSign):
    global ec_signature
    ec_signature = ec_key.sign(toSign.encode(),ec.ECDSA(hashes.SHA256()))



def verifyDSASignature(signature):
   dsa_pubkey.verify(signature, toSign.encode(), hashes.SHA256())

def verifyRSASignature(signature):
    rsa_pubkey.verify(signature, toSign.encode(), rsa_padding, hashes.SHA256())

def verifyECDSASignature(signature):
    ec_pubkey.verify(signature, toSign.encode(), ec.ECDSA(hashes.SHA256()))


if __name__ == "__main__":
    toSign = "This is a test message"
    runs = 100
    generateRSASignatrue(toSign)
    generateDSASignatrue(toSign)
    generateECDSASignatrue(toSign)
    verifyRSASignature(rsa_signature)
    verifyDSASignature(dsa_signature)
    verifyECDSASignature(ec_signature)
    print("All signatures are valid")
    print("----------------------------------------")
    print("length of the message: ", len(toSign), "bytes")
    print("length of the rsa signature: ", len(rsa_signature), "bytes")
    print("length of the dsa signature: ", len(dsa_signature), "bytes")
    print("length of the ecdsa signature: ", len(ec_signature), "bytes")



    print("Timing:")

    execution_time_rsa_sign = timeit.timeit(lambda: generateRSASignatrue(toSign), number=runs)
    execution_time_dsa_sign = timeit.timeit(lambda: generateDSASignatrue(toSign), number=runs)
    execution_time_ecdsa_sign = timeit.timeit(lambda: generateECDSASignatrue(toSign), number=runs)
    execution_time_rsa_verify = timeit.timeit(lambda: verifyRSASignature(rsa_signature), number=runs)
    execution_time_dsa_verify = timeit.timeit(lambda: verifyDSASignature(dsa_signature), number=runs)
    execution_time_ecdsa_verify = timeit.timeit(lambda: verifyECDSASignature(ec_signature), number=runs)

    print(f"Average over {runs} runs (ms):")
    print(f"{'RSA':} {execution_time_rsa_sign / runs * 1000:8.3f} {execution_time_rsa_verify / runs * 1000:8.3f}")
    print(f"{'DSA':} {execution_time_dsa_sign / runs * 1000:8.3f} {execution_time_dsa_verify / runs * 1000:8.3f}")
    print(f"{'ECDSA':} {execution_time_ecdsa_sign / runs * 1000:8.3f} {execution_time_ecdsa_verify / runs * 1000:8.3f}")

    print("Computational Cost in CPU cycles:")
