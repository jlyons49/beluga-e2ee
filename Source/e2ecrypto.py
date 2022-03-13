from inspect import signature
import os
import sys
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat, load_pem_private_key, BestAvailableEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import cryptography.exceptions
import zlib

def generatePrivateKey():
    return ec.generate_private_key(ec.SECP384R1())

def getMyPublicKey(private_key: ec.EllipticCurvePrivateKey):
    try: 
        return private_key.public_key()
    except:
        raise TypeError('generatePublicKey: must provide EllipticCurvePrivateKey')

def privateKeyToPEM(private_key: ec.EllipticCurvePrivateKey):
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b'e2e-system')).decode('ascii')

def privateKeyFromPEM(pem_private_key: str):
    pem_bytes = bytes(pem_private_key, 'ascii')
    private_key = load_pem_private_key(pem_bytes, password=b'e2e-system')
    return private_key

def publicKeyToBytes(public_key: ec.EllipticCurvePublicKey):
    return public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

def bytesToPublicKey(public_key_bytes: bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), public_key_bytes)

def initiateECDH():
    private_key = generatePrivateKey()
    public_key = getMyPublicKey(private_key)

    return private_key,public_key

def completeECDH(private_key: ec.EllipticCurvePrivateKey, received_public_key: ec.EllipticCurvePublicKey):
    public_key = 0
    if private_key == None:
        private_key = generatePrivateKey()
        public_key = getMyPublicKey(private_key)
    shared_key = HKDF(hashes.SHA256(), 32,None,None).derive(private_key.exchange(ec.ECDH(), received_public_key))

    return shared_key, public_key

# Encrypts the byte array secret_message with key
def encrypt(secret_message, key):
    compressed_message = zlib.compress(secret_message)
    while len(compressed_message)%16 != 0 :
        compressed_message = b'\0' + compressed_message

    # Create random key and IV (should be replaced with more secure method later)
    iv = os.urandom(16)

    # Generate the ciphertext and tag
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(compressed_message) + encryptor.finalize()
    tag = encryptor.tag
   
    return ciphertext, iv, tag

# Decrypts byte array ciphertext with key and returns decrypted byte array
def decrypt(ciphertext, iv, tag, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    try:
        compressed_message = decryptor.update(ciphertext) + decryptor.finalize()
    except cryptography.exceptions.InvalidTag:
        raise RuntimeError('Failure to decrypt!')
    compressed_message = compressed_message.strip(b'\0')
    plaintext = zlib.decompress(compressed_message)

    return plaintext

def sign(byte_array, private_key: ec.EllipticCurvePrivateKey):
    if isinstance(byte_array, str):
        return private_key.sign(bytes(byte_array, 'ascii'), ec.ECDSA(hashes.SHA256()))
    elif isinstance(byte_array, bytes):
        return private_key.sign(byte_array, ec.ECDSA(hashes.SHA256()))
    else:
        raise TypeError    

def verify(byte_array: bytes, signature: bytes, pubic_key: ec.EllipticCurvePublicKeyWithSerialization):
    try :
        pubic_key.verify(signature, byte_array, ec.ECDSA(hashes.SHA256()))
    except cryptography.exceptions.InvalidSignature:
        #print("INVALID SIGNATURE")
        return False
    return True

