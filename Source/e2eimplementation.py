import base64
from e2ecrypto import *
from e2ejson import *

class e2eSystem():

    def __init__(self, password=""):
        try:
            self.db = jsonDatabase("./", password)
        except RuntimeError:
            raise RuntimeError('Failure to decrypt, password incorrect or file may be corrupted!')
        self.signingKey = None
        self.ActivePrivateSecret = None

        try:
            signingkeyPEM = self.db.getSigningKey()
            self.signingKey = privateKeyFromPEM(signingkeyPEM)
        except RuntimeError:
            signingkey = generatePrivateKey()
            signingKeyPEM = privateKeyToPEM(signingkey)
            self.db.setSigningKey(signingKeyPEM)

    def sendEncryptedMessage(self, user_id, secret_message):
        #TODO: need to have a lookup for user to session
        session_id = user_id
        try:
            key = self.db.getSessionKey(session_id)
        except RuntimeError:
            print("No active session for user: " + user_id)
            return []
        encrypted_message_bytes, iv, tag = encrypt(bytes(secret_message,'ascii'), key)
        iv85 = base64.b85encode(iv).decode('ascii')
        tag85 = base64.b85encode(tag).decode('ascii')
        qrmsgs = []
        if(len(encrypted_message_bytes)<140):
            msg85 = base64.b85encode(encrypted_message_bytes).decode('ascii')
            msgJSON = {"mode":1,"iv":iv85, "ct":msg85, "tag":tag85}
            qrmsgs = [json.dumps(msgJSON)]
        else:
            chunk_count = len(encrypted_message_bytes)//140
            print("chunk count: " + str(chunk_count))
            for i in range(0,chunk_count+1):
                msg85 = base64.b85encode(encrypted_message_bytes[(i*140):((i+1)*140)]).decode('ascii')
                msgJSON = {"mode":2,"index":i,"total":chunk_count+1,"iv":iv85, "ct":msg85, "tag":tag85}
                qrmsgs.append(json.dumps(msgJSON))
        return qrmsgs


    def receiveEncryptedMessage(self, user_id, encrypted_message, iv, tag):
        #TODO: need to have a lookup for user to session
        session_id = user_id
        try:
            key = self.db.getSessionKey(session_id)
        except RuntimeError:
            print("No active session for user: " + user_id)
            return None
        encrypted_message_bytes = base64.b85decode(encrypted_message)
        message_bytes = decrypt(encrypted_message_bytes, base64.b85decode(iv), base64.b85decode(tag), key)
        return message_bytes.decode('ASCII')

    def initializeSession(self, user_id):
        try:
            publicKey = bytesToPublicKey(self.db.getPublicKey(user_id))
        except RuntimeError:
            print("\nERROR: No public key for provided id!\n\n")
            return None,None
        PrivateSecret, PublicSecret = initiateECDH()
        public_secret_bytes = publicKeyToBytes(PublicSecret)
        signature = sign(public_secret_bytes,privateKeyFromPEM(self.db.getSigningKey()))
        ps85 = base64.b85encode(public_secret_bytes).decode('ascii')
        sig85 = base64.b85encode(signature).decode('ascii')
        msgJSON = {"mode":3,"sec":ps85, "sig":sig85}
        qrmsg = json.dumps(msgJSON)
        self.ActivePrivateSecret = PrivateSecret
        return qrmsg

    def acceptSessionInit(self, user_id, received_secret_b85, recevied_signature_b85):
        try:
            publicKey = bytesToPublicKey(self.db.getPublicKey(user_id))
        except RuntimeError:
            print("\n\ERROR: No public key for provided id!\n\n")
            return None

        new_initiation = False

        if(self.ActivePrivateSecret == None):
            self.ActivePrivateSecret, PublicSecret = initiateECDH()
            new_initiation = True
        else:
            PublicSecret = getMyPublicKey(self.ActivePrivateSecret)

        if(received_secret_b85 == None):
            print("\n\n")
            received_secret_b85 = input("Please enter provided secret: ")
            recevied_signature_b85 = input("Please enter provided signature: ")
        
        # Verify the received secret
        received_secret_bytes = base64.b85decode(received_secret_b85)
        recevied_signature_bytes = base64.b85decode(recevied_signature_b85)
        if(verify(received_secret_bytes,recevied_signature_bytes,publicKey) == False):
            print("\n----------\nERROR: Failed to verify signature!\n----------\n")
            return None

        # Calculate Shared Secret
        received_secret = bytesToPublicKey(received_secret_bytes)
        shared_secret, _ = completeECDH(self.ActivePrivateSecret, received_secret)
        print("Session Initialized for user: "+ user_id)
        print("\n\n")
        self.db.saveSessionKey(user_id, shared_secret)
        self.ActivePrivateSecret = None

        # Provide new public secret if new session initiation
        if(new_initiation):
            public_secret_bytes = publicKeyToBytes(PublicSecret)
            signature = sign(public_secret_bytes,privateKeyFromPEM(self.db.getSigningKey()))
            ps85 = base64.b85encode(public_secret_bytes).decode('ascii')
            sig85 = base64.b85encode(signature).decode('ascii')
            msgJSON = {"mode":3,"sec":ps85, "sig":sig85}
            qrmsg = json.dumps(msgJSON)
            return qrmsg
        
        return None
        

    def sharePublicKeys(self):
        publicKey = publicKeyToBytes(getMyPublicKey(privateKeyFromPEM(self.db.getSigningKey())))
        publicKey_85 = base64.b85encode(publicKey).decode('ascii')
        msgJSON = {"mode":6,"publickey":publicKey_85}
        qrmsg = json.dumps(msgJSON)
        return qrmsg

    def receivePublicKey(self, user_id, received_pub_key_b85):
        public_key = base64.b85decode(received_pub_key_b85)
        self.db.storePublicKey(user_id, public_key)