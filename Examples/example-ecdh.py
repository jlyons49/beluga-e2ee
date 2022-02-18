from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat, load_pem_private_key, BestAvailableEncryption
import base64
import json
import sys

if len(sys.argv) < 2:
    mode = input("Please input mode: ")
    filename = input("Please input output file name: ")
else:
    mode = sys.argv[1]
    filename = sys.argv[2]

if mode == "0":
    privateKey = ec.generate_private_key(ec.SECP384R1())
    privateKeyPEM = privateKey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b'nothanks')).decode('ascii')
    publicKey = privateKey.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    pubKey85 = base64.b85encode(publicKey).decode('ascii')
    print("Generating Public Key File...")
    jsondata = {"mode":"0", "pubKey":pubKey85}
    with open(filename,"w") as dataFile:
        json.dump(jsondata, dataFile)
    print("Public Key: " + pubKey85)
    rxPublicKey = input("Please enter received base85 encoded public key: ")
    rxPublicKey = base64.b85decode(rxPublicKey)
    rxPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), rxPublicKey)
    dataFile.close()
    shared_key = HKDF(hashes.SHA256(), 32,None,None).derive(privateKey.exchange(ec.ECDH(), rxPublicKey))
    shared_key85 = base64.b85encode(shared_key).decode('ascii')
    print("Generating Session Key File...")
    jsondata = {"sessionKey":shared_key85}
    with open('sessionFile2.json',"w") as dataFile:
        json.dump(jsondata, dataFile)
    print("Session Key: " + shared_key85)

elif mode == "1":
    dataFile = open(filename)
    jsondata = json.load(dataFile)
    mode = base64.b85decode(jsondata['mode'])
    pubKey = base64.b85decode(jsondata['pubKey'])
    rxPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), pubKey)
    dataFile.close()
    
    privateKey = ec.generate_private_key(ec.SECP384R1())
    publicKey = privateKey.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    pubKey85 = base64.b85encode(publicKey).decode('ascii')
    
    print("Generating Public Key File...")
    jsondata = {"mode":"1", "pubKey":pubKey85}
    with open(filename,"w") as dataFile:
        json.dump(jsondata, dataFile)
    print("Public Key: " + pubKey85)

    shared_key = HKDF(hashes.SHA256(), 32,None,None).derive(privateKey.exchange(ec.ECDH(), rxPublicKey))
    shared_key85 = base64.b85encode(shared_key).decode('ascii')
    print("Generating Session Key File...")
    jsondata = {"sessionKey":shared_key85}
    with open('sessionFile1.json',"w") as dataFile:
        json.dump(jsondata, dataFile)
    print("Session Key: " + shared_key85)

if mode == "4":
    privateKey = ec.generate_private_key(ec.SECP384R1())
    privateKeyPEM = privateKey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b'nothanks')).decode('ascii')
    publicKey = privateKey.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    pubKey85 = base64.b85encode(publicKey).decode('ascii')
    print("Generating Public Key File...")
    jsondata = {"mode":"0", "pubKey":pubKey85}
    with open(filename,"w") as dataFile:
        json.dump(jsondata, dataFile)
    jsondata = {"myPrivKey":privateKeyPEM}
    with open('myPrivKey.json',"w") as dataFile:
        json.dump(jsondata, dataFile)

elif mode == "5":
    dataFile = open('myPrivKey.json')
    jsondata = json.load(dataFile)
    pemdata = bytes(jsondata['myPrivKey'], 'ascii')
    privateKey = load_pem_private_key(pemdata, password=b'nothanks')
    dataFile = open(filename)
    jsondata = json.load(dataFile)
    mode = base64.b85decode(jsondata['mode'])
    pubKey = base64.b85decode(jsondata['pubKey'])
    rxPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), pubKey)
    dataFile.close()
    shared_key = HKDF(hashes.SHA256(), 32,None,None).derive(privateKey.exchange(ec.ECDH(), rxPublicKey))
    shared_key85 = base64.b85encode(shared_key).decode('ascii')
    print("Generating Session Key File...")
    jsondata = {"sessionKey":shared_key85}
    with open('sessionFile2.json',"w") as dataFile:
        json.dump(jsondata, dataFile)
    print("Session Key: " + shared_key85)
