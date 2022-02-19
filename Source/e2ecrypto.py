from inspect import signature
import os
import sys
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import cryptography.exceptions
import json
import base64
import unittest
import random

def generatePrivateKey():
    return ec.generate_private_key(ec.SECP384R1())

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
    return private_key.sign(byte_array, ec.ECDSA(hashes.SHA256()))

def signString(string, private_key: ec.EllipticCurvePrivateKey):
    return private_key.sign(bytes(string, 'ascii'), ec.ECDSA(hashes.SHA256()))

def verify(byte_array: bytes, signature: bytes, pubic_key: ec.EllipticCurvePublicKeyWithSerialization):
    try :
        pubic_key.verify(signature, byte_array, ec.ECDSA(hashes.SHA256()))
    except cryptography.exceptions.InvalidSignature:
        print("INVALID SIGNATURE")
    return 0

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
        

