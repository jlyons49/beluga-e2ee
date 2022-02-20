import os
import sys
import json
import unittest
import random
import base64

signingFile = "signingKey.json"

def saveSessionKey(id: str, key: bytes):
    try:
        jsonFile = open("sessionFile.json", "r")
        data = json.load(jsonFile)
        jsonFile.close()
    except:
        data = {}

    data[id] = base64.b85encode(key).decode('ascii')

    with open("sessionFile.json", "w") as jsonFile:
        json.dump(data, jsonFile, indent="")

def getSessionKey(id):
    try:
        jsonFile = open("sessionFile.json", "r")
        data = json.load(jsonFile)
        jsonFile.close()
    except:
        raise RuntimeError('No session for provided id')
    
    return base64.b85decode(data[id])

def removeSession(id):
    try:
        jsonFile = open("sessionFile.json", "r")
        data = json.load(jsonFile)
        jsonFile.close()
    except:
        return -1

    data.pop(id)

    with open("sessionFile.json", "w") as jsonFile:
        json.dump(data, jsonFile, indent="")
    
    return 0

def setSigningKey(key):
    data = {"signingKey":key}  
    with open("signingKey.json", "w") as jsonFile:
        json.dump(data,jsonFile, indent="")

def getSigningKey():
    try:
        jsonFile = open("signingKey.json", "r")
        data = json.load(jsonFile)
        jsonFile.close()
    except:
        raise RuntimeError('No Signing Key Present')
    
    return data["signingKey"]

def storePublicKey(id, public_key):
    try:
        jsonFile = open("publicKeys.json", "r")
        data = json.load(jsonFile)
        jsonFile.close()
    except:
        data = {}

    data[id] = base64.b85encode(public_key).decode('ascii')

    with open("publicKeys.json", "w") as jsonFile:
        json.dump(data, jsonFile, indent="")

def getPublicKey(id):
    try:
        jsonFile = open("publicKeys.json", "r")
        data = json.load(jsonFile)
        jsonFile.close()
    except:
        raise RuntimeError('No public key for provided id')
    
    return base64.b85decode(data[id])

def removePublicKey(id):
    try:
        jsonFile = open("publicKeys.json", "r")
        data = json.load(jsonFile)
        jsonFile.close()
    except:
        return -1

    data.pop(id)

    with open("publicKeys.json", "w") as jsonFile:
        json.dump(data, jsonFile, indent="")
    
    return 0

class TestE2EJson(unittest.TestCase):
    def test_save_and_load_session(self):
        id = str('').join(random.choices('123456789', k=16))
        key = os.urandom(32)
        saveSessionKey(id,key)
        key2 = getSessionKey(id)
        self.assertEqual(key, key2)
        removeSession(id)

    def test_save_and_load_signingKey(self):
        key = base64.b85encode(os.urandom(384)).decode('ascii')
        setSigningKey(key)
        key2 = getSigningKey()
        self.assertEqual(key, key2)

    def test_save_and_load_publicKey(self):
        id = str('').join(random.choices('123456789', k=16))
        key = os.urandom(84)
        storePublicKey(id, key)
        key2 = getPublicKey(id)
        self.assertEqual(key, key2)
        removePublicKey(id)