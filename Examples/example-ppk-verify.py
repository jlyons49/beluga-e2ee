from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import exceptions
import sys
import base64
import json

dataFile = open('dataFile.json')
jsondata = json.load(dataFile)

data = base64.b85decode(jsondata['data'])
signature = base64.b85decode(jsondata['sig'])
pubKey = base64.b85decode(jsondata['pubKey'])

publicKey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), pubKey)

try :
    publicKey.verify(signature, data, ec.ECDSA(hashes.SHA256()))
except exceptions.InvalidSignature:
    print("INVALID SIGNATURE")
    exit()

print("Signature Validated!")