from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend
from cryptography import exceptions

privateKey = ec.generate_private_key(ec.SECP384R1(), default_backend())
publicKey = privateKey.public_key()

data = b'This is an example string to be signed'

signature = privateKey.sign(data, ec.ECDSA(hashes.SHA256()))

try :
    publicKey.verify(signature, data, ec.ECDSA(hashes.SHA256()))
except exceptions.InvalidSignature:
    print("INVALID SIGNATURE")
    exit()

print("Signature Validated!")
