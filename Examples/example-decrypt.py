import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64


dataFile = open('dataFile.json')
data = json.load(dataFile)

key = base64.b85decode(data['key'])
iv = base64.b85decode(data['iv'])
tag = base64.b85decode(data['tag'])

cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), default_backend())
decryptor = cipher.decryptor()
pt = decryptor.update(base64.b85decode(data['ct'])) + decryptor.finalize()

print("decrypted message: \"" + pt.decode('ASCII').partition('`')[0] + "\"")
