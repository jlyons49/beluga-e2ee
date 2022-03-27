import os
import sys
import json
import unittest
import random
import base64
from fileencrypter import *

signingFile = "signingKey.json"

class jsonDatabase():

    def __init__(self, root_directory="./", password=""):
        self.root_directory = root_directory
        self.database_loaded = False
        self.database = None
        self.passwordHash = passwordHasher(password)
        try:
            self.loadDatabase()
        except RuntimeError:
            raise RuntimeError('Failure to decrypt, password incorrect or file may be corrupted!')

    def loadDatabase(self):
        if self.database_loaded:
            return True
        try:
            # jsonFile = open(self.root_directory+"database.json", "r")
            self.database = json.loads(loadEncryptedFile(self.root_directory+"database.json", self.passwordHash))
            # jsonFile.close()
        except FileNotFoundError:
            self.database = {'signingKey':None,'sessionKeys':{},'publicKeys':{}}
        except RuntimeError:
            raise RuntimeError('Failure to decrypt, password incorrect or file may be corrupted!')
        self.database_loaded = True
        return True

    def saveDatabase(self):
        if self.database_loaded == False:
            return False
        # with open(self.root_directory+"database.json", "w") as jsonFile:
        json_string = json.dumps(self.database, indent="")
        # jsonFile.write(json_string)
        saveEncryptedFile(self.root_directory+"database.json", json_string, self.passwordHash)
        return True


    def saveSessionKey(self,id: str, key: bytes):
        self.database['sessionKeys'][id] = base64.b85encode(key).decode('ascii')
        self.saveDatabase()

    def getSessionKey(self,id):
        session_key = self.database['sessionKeys'].get(id)
        if(session_key == None):
            raise RuntimeError('No session for id!')
        else:
            return base64.b85decode(session_key)

    def removeSession(self,id):
        self.database['sessionKeys'].pop(id)
        self.saveDatabase()

    def setSigningKey(self,key):
        self.database['signingKey'] = key
        self.saveDatabase()
        

    def getSigningKey(self):
        if "signingKey" in self.database.keys():
            signing_key = self.database["signingKey"]
        if signing_key != None:
            return self.database["signingKey"]
        else:
            raise RuntimeError('No Signing Key Present')

    def storePublicKey(self,id, public_key):
        self.database['publicKeys'][id] = base64.b85encode(public_key).decode('ascii')
        self.saveDatabase()

    def getPublicKey(self,id):
        public_key = self.database['publicKeys'].get(id)
        if(public_key == None):
            raise RuntimeError('No public key for id!')
        else:
            return base64.b85decode(public_key)
        
    def removePublicKey(self,id):
        self.database['publicKeys'].pop(id)
        self.saveDatabase()
