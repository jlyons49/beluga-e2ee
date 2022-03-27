import cryptography
import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import base64
import zlib
import json


def loadEncryptedFile(file_path, passwordHash):
    decrypted_contents = ""
    try:
        with open(file_path, "r") as encrypted_file:
            file_json = json.load(encrypted_file)
    except:
        raise FileNotFoundError

    iv = base64.b85decode(file_json['iv'])
    tag = base64.b85decode(file_json['tag'])
    ciphertext = base64.b85decode(file_json['ct'])
    cipher = Cipher(algorithms.AES(passwordHash), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    try:
        compressed_message = decryptor.update(ciphertext) + decryptor.finalize()
    except cryptography.exceptions.InvalidTag:
        raise RuntimeError('Failure to decrypt, password incorrect or file may be corrupted!')
    compressed_message = compressed_message.strip(b'\0')
    decrypted_contents = zlib.decompress(compressed_message)

    return decrypted_contents.decode('ASCII')

def saveEncryptedFile(file_path, file_contents, passwordHash):

    compressed_message = zlib.compress(bytes(file_contents,'ascii'))
    while len(compressed_message)%16 != 0 :
        compressed_message = b'\0' + compressed_message

    # Create random key and IV (should be replaced with more secure method later)
    iv = os.urandom(16)

    # Generate the ciphertext and tag
    cipher = Cipher(algorithms.AES(passwordHash), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(compressed_message) + encryptor.finalize()
    tag = encryptor.tag

    data85= base64.b85encode(ciphertext).decode('ascii')
    iv85 = base64.b85encode(iv).decode('ascii')
    tag85 = base64.b85encode(tag).decode('ascii')
    json_data = {"iv":iv85, "tag":tag85, "ct":data85}
    with open(file_path, "w") as jsonFile:
        json.dump(json_data, jsonFile, indent="")
   
    return True

def passwordHasher(password):
    passwordHash = HKDF(hashes.SHA256(),32,bytes('girefub3', 'ascii'),None).derive(bytes(password,'ascii'))
    return passwordHash