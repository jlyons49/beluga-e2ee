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
        self.database_loaded = False
        self.database = None

    def loadDatabase(self):
        if self.database_loaded:
            return True
        try:
            jsonFile = open(self.root_directory+"database.json", "r")
            self.database = json.load(jsonFile)
            jsonFile.close()
        except FileNotFoundError:
            self.database = {'signingKey':None,'sessionKeys':{},'publicKeys':{}}
        self.database_loaded = True
        return True

    def saveDatabase(self):
        if self.database_loaded == False:
            return False
        with open(self.root_directory+"database.json", "w") as jsonFile:
            json_string = json.dumps(self.database, indent="")
            jsonFile.write(json_string)
        return True


    def saveSessionKey(self,id: str, key: bytes):
        self.loadDatabase()
        self.database['sessionKeys'][id] = base64.b85encode(key).decode('ascii')
        self.saveDatabase()

    def getSessionKey(self,id):
        self.loadDatabase()
        session_key = self.database['sessionKeys'].get(id)
        if(session_key == None):
            raise RuntimeError('No session for id!')
        else:
            return base64.b85decode(session_key)

    def removeSession(self,id):
        self.loadDatabase()
        self.database['sessionKeys'].pop(id)
        self.saveDatabase()

    def setSigningKey(self,key):
        self.loadDatabase()
        self.database['signingKey'] = key
        self.saveDatabase()
        

    def getSigningKey(self):
        self.loadDatabase()
        if "signingKey" in self.database.keys():
            signing_key = self.database["signingKey"]
        if signing_key != None:
            return self.database["signingKey"]
        else:
            raise RuntimeError('No Signing Key Present')

    def storePublicKey(self,id, public_key):
        self.loadDatabase()
        self.database['publicKeys'][id] = base64.b85encode(public_key).decode('ascii')
        self.saveDatabase()

    def getPublicKey(self,id):
        self.loadDatabase()
        public_key = self.database['publicKeys'].get(id)
        if(public_key == None):
            raise RuntimeError('No public key for id!')
        else:
            return base64.b85decode(public_key)
        
    def removePublicKey(self,id):
        self.loadDatabase()
        self.database['publicKeys'].pop(id)
        self.saveDatabase()
