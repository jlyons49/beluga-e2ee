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
        return base64.b85decode(data[id])
    except KeyError:
        raise RuntimeError('No public key for provided id')
    
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
