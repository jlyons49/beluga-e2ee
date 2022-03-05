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
import unittest
import random

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
    if len(secret_message)%16 != 0 : secret_message = secret_message + b'`'
    while len(secret_message)%16 != 0 :
        secret_message = secret_message + b'0'

    # Create random key and IV (should be replaced with more secure method later)
    iv = os.urandom(16)

    # Generate the ciphertext and tag
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(secret_message) + encryptor.finalize()
    tag = encryptor.tag
   
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    pt = decryptor.update(ciphertext) + decryptor.finalize()

    return ciphertext, iv, tag

# Decrypts byte array ciphertext with key and returns decrypted byte array
def decrypt(ciphertext, iv, tag, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except cryptography.exceptions.InvalidTag:
        raise RuntimeError('Bad tag!')
    plaintext = bytes(plaintext.decode('ASCII').partition('`')[0], 'ascii')

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

class TestE2ECrypto(unittest.TestCase):
    def test_encrypt_then_decrypt(self):
        testString = str("This is just a test").encode('ASCII')
        key = os.urandom(32)
        encrypted, iv, tag = encrypt(testString, key)
        decrypted = decrypt(encrypted, iv, tag, key)
        self.assertEqual(testString, bytes(decrypted))
    
    def test_longencrypt(self):
        testString = str('').join(random.choices('123456789', k=32768)).encode('ASCII')
        key = os.urandom(32)
        encrypted, iv, tag = encrypt(testString, key)
        self.assertNotEqual(testString,encrypted)
        self.assertEqual(len(encrypted),32768)

    def test_decrypt_tag_failure(self):
        testString = str("This is just a test").encode('ASCII')
        key = os.urandom(32)
        encrypted, iv, tag = encrypt(testString, key)
        with self.assertRaises(RuntimeError):
            decrypt(encrypted, iv, b'0'*16, key)

    def test_decrypt_key_failure(self):
        testString = str("This is just a test").encode('ASCII')
        key = os.urandom(32)
        encrypted, iv, tag = encrypt(testString, key)
        with self.assertRaises(RuntimeError):
            decrypt(encrypted, iv, tag, bytearray(32))

    def test_sign_and_verify(self):
        testString = str('').join(random.choices('123456789', k=32768)).encode('ASCII')
        private_key = generatePrivateKey()
        public_key = private_key.public_key()
        signature = sign(testString,private_key)
        self.assertEqual(verify(testString,signature,public_key),0)
        
    def test_ECDH(self):
        private_key, public_key_1 = initiateECDH()
        shared_key_1, public_key_2 = completeECDH(None, public_key_1)
        shared_key_2, pkholder = completeECDH(private_key, public_key_2)
        self.assertEqual(shared_key_1,shared_key_2)
