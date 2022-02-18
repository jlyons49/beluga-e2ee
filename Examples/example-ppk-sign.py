from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import exceptions
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import sys
import base64
import json

privateKey = ec.generate_private_key(ec.SECP384R1())

publicKey = privateKey.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
pubKey85 = base64.b85encode(publicKey).decode('ascii')

if len(sys.argv) < 2:
    data = input("Please data to be signed: ").encode('ASCII')
else:
    try:
        data = sys.argv[1].encode('ASCII')
    except TypeError:
        print("Argument is not a string!")
        quit()

data85 = base64.b85encode(data).decode('ascii')

signature = privateKey.sign(data, ec.ECDSA(hashes.SHA256()))
sig85 = base64.b85encode(signature).decode('ascii')
print("Signature (b85): " + sig85)

# Save the output to a file
jsondata = {"data":data85, "sig":sig85, "pubKey":pubKey85}
with open("dataFile.json","w") as dataFile:
    json.dump(jsondata, dataFile)
