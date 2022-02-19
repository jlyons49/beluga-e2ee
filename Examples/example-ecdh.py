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
else:
    mode = sys.argv[1]
if len(sys.argv) < 3:
    filename = input("Please input output file name: ")
else:
    filename = sys.argv[2]

# Mode 0 generates a public key for use in another user's mode 1, then waits to receive their public key
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
    with open('sessionFile1.json',"w") as dataFile:
        json.dump(jsondata, dataFile)
    print("Session Key: " + shared_key85)

# Mode 1 receives another user's public key, generates a public key itself, and generates the shared secret
elif mode == "1":
    rxPublicKey = input("Please enter received base85 encoded public key: ")
    rxPublicKey = base64.b85decode(rxPublicKey)
    rxPublicKey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), rxPublicKey)
    
    privateKey = ec.generate_private_key(ec.SECP384R1())
    publicKey = privateKey.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    pubKey85 = base64.b85encode(publicKey).decode('ascii')
    print("Public Key: " + pubKey85)
    
    shared_key = HKDF(hashes.SHA256(), 32,None,None).derive(privateKey.exchange(ec.ECDH(), rxPublicKey))
    shared_key85 = base64.b85encode(shared_key).decode('ascii')
    print("Generating Session Key File...")
    jsondata = {"sessionKey":shared_key85}
    with open('sessionFile2.json',"w") as dataFile:
        json.dump(jsondata, dataFile)
    print("Session Key: " + shared_key85)

# Mode 2 receives another user's public key, generates a public key itself, and generates the shared secret
elif mode == "2":
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
    with open('sessionFile2.json',"w") as dataFile:
        json.dump(jsondata, dataFile)
    print("Session Key: " + shared_key85)

# Mode 4 generates a public key for use in another user's mode 1 and stores the private key for mode 5
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

# Mode 5 receives a public key, opens the stored private key, and generates the shared secret
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
