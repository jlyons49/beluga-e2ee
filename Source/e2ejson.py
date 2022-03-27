import os
import sys
import json
import unittest
import random
import base64

signingFile = "signingKey.json"

class jsonDatabase():

    def __init__(self, root_directory="./"):
        self.root_directory = root_directory

    def saveSessionKey(self,id: str, key: bytes):
        try:
            jsonFile = open(self.root_directory+"sessionFile.json", "r")
            data = json.load(jsonFile)
            jsonFile.close()
        except FileNotFoundError:
            data = {}

        data[id] = base64.b85encode(key).decode('ascii')

        with open(self.root_directory+"sessionFile.json", "w") as jsonFile:
            json.dump(data, jsonFile, indent="")

    def getSessionKey(self,id):
        try:
            jsonFile = open(self.root_directory+"sessionFile.json", "r")
            data = json.load(jsonFile)
            jsonFile.close()
        except:
            raise RuntimeError('No session file!')

        if(data.get(id) == None):
            raise RuntimeError('No session for id!')
        
        return base64.b85decode(data[id])

    def removeSession(self,id):
        try:
            jsonFile = open(self.root_directory+"sessionFile.json", "r")
            data = json.load(jsonFile)
            jsonFile.close()
        except FileNotFoundError:
            return -1

        data.pop(id)

        with open(self.root_directory+"sessionFile.json", "w") as jsonFile:
            json.dump(data, jsonFile, indent="")
        
        return 0

    def setSigningKey(self,key):
        data = {"signingKey":key}  
        with open(self.root_directory+"signingKey.json", "w") as jsonFile:
            json.dump(data,jsonFile, indent="")

    def getSigningKey(self):
        try:
            jsonFile = open(self.root_directory+"signingKey.json", "r")
            data = json.load(jsonFile)
            jsonFile.close()
        except FileNotFoundError:
            raise RuntimeError('No Signing Key Present')
        
        return data["signingKey"]

    def storePublicKey(self,id, public_key):
        try:
            jsonFile = open(self.root_directory+"publicKeys.json", "r")
            data = json.load(jsonFile)
            jsonFile.close()
        except FileNotFoundError:
            data = {}

        data[id] = base64.b85encode(public_key).decode('ascii')

        with open(self.root_directory+"publicKeys.json", "w") as jsonFile:
            json.dump(data, jsonFile, indent="")

    def getPublicKey(self,id):
        try:
            jsonFile = open(self.root_directory+"publicKeys.json", "r")
            data = json.load(jsonFile)
            jsonFile.close()
            return base64.b85decode(data[id])
        except (FileNotFoundError, KeyError):
            raise RuntimeError('No public key for provided id')
        
    def removePublicKey(self,id):
        try:
            jsonFile = open(self.root_directory+"publicKeys.json", "r")
            data = json.load(jsonFile)
            jsonFile.close()
        except FileNotFoundError:
            return -1

        data.pop(id)

        with open(self.root_directory+"publicKeys.json", "w") as jsonFile:
            json.dump(data, jsonFile, indent="")
        
        return 0
