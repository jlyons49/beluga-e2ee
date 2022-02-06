from dataclasses import InitVar
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import base64

if len(sys.argv) < 2:
    secret_message = input("Please provide a secret message: ").encode('ASCII')
else:
    try:
        secret_message = sys.argv[1].encode('ASCII')
    except TypeError:
        print("Argument is not a string!")
        quit()

while len(secret_message)%16 != 0 :
    secret_message = secret_message + b'0'

# Pad the message if not length
print("msg with pad: \"" + secret_message.decode('ASCII') + "\"")

# Load key (static for now)
key = os.urandom(32)
key85 = base64.b85encode(key).decode('ascii')

# Create random key and IV (should be replaced with more secure method later)
iv = os.urandom(16)
iv85 = base64.b85encode(iv).decode('ascii')
print("key (b85): " + key85)
print("iv (b85): " + iv85)

# Generate the ciphertext
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
encryptor = cipher.encryptor()
ct = encryptor.update(secret_message) + encryptor.finalize()
ct85 = base64.b85encode(ct).decode('ascii')
print("cyphertext (b85): " + ct85)

# Save the output to a file
data = {"key":key85, "iv":iv85, "ct":ct85}
with open("dataFile.json","w") as dataFile:
    json.dump(data, dataFile)
