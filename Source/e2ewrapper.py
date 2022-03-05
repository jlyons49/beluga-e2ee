from e2ecrypto import *
from e2ejson import *

#TODO: remove dependencies by making a new module
import base64

# TODO: Move to other module
def sendEncryptedMessage(user_id, secret_message):
    #TODO: need to have a lookup for user to session
    session_id = user_id
    try:
        key = getSessionKey(session_id)
    except RuntimeError:
        print("No active session for user: " + user_id)
    encrypted_message_bytes, iv, tag = encrypt(bytes(secret_message,'ascii'), key)
    print('\n----------------------------------')
    print("This is your encrypted message (b85):\n" + base64.b85encode(encrypted_message_bytes).decode('ascii'))
    print("This is your iv (b85):\n" + base64.b85encode(iv).decode('ascii'))
    print("This is your tag (b85):\n" + base64.b85encode(tag).decode('ascii'))
    print('----------------------------------\n')

# TODO: Move to other module
def receiveEncryptedMessage(user_id, encrypted_message, iv, tag):
    #TODO: need to have a lookup for user to session
    session_id = user_id
    try:
        key = getSessionKey(session_id)
    except RuntimeError:
        print("No active session for user: " + user_id)
    encrypted_message_bytes = base64.b85decode(encrypted_message)
    message_bytes = decrypt(encrypted_message_bytes, base64.b85decode(iv), base64.b85decode(tag), key)
    print("\n\n")
    print("This is your secret message:\n----------\n" + message_bytes.decode('ASCII'))
    print("\n\n")

# TODO: Move to other module
def initializeSession(userId):
    try:
        publicKey = bytesToPublicKey(getPublicKey(userId))
    except RuntimeError:
        print("\n\ERROR: No public key for provided id!\n\n")
        return None
    PrivateSecret, PublicSecret = initiateECDH()
    public_secret_bytes = publicKeyToBytes(PublicSecret)
    signature = sign(public_secret_bytes,privateKeyFromPEM(getSigningKey()))
    print("\n\n")
    print("Please provide this public secret to the other user:\n----------\n" + base64.b85encode(public_secret_bytes).decode('ascii'))
    print("\nPlease provide this signature to the other user:\n----------\n" + base64.b85encode(signature).decode('ascii'))
    print("\n\n")
    recevied_secret_b85 = input("Please enter provided secret (or enter to delay): ")
    if(recevied_secret_b85 == ""):
        return PrivateSecret
    received_secret_bytes = base64.b85decode(recevied_secret_b85)
    recevied_signature_b85 = input("Please enter provided signature: ")
    recevied_signature_bytes = base64.b85decode(recevied_signature_b85)
    if(verify(received_secret_bytes,recevied_signature_bytes,publicKey) == False):
        print("\n----------\nERROR: Failed to verify signature!\n----------\n")
        return None
    received_secret = bytesToPublicKey(received_secret_bytes)
    shared_secret,pkholder = completeECDH(PrivateSecret, received_secret)
    print("\n\n")
    print("Session Initialized for user: "+ userId)
    print("\n\n")
    saveSessionKey(userId, shared_secret)
    return PrivateSecret

def acceptSessionInit(userId, active_private_key):
    try:
        publicKey = bytesToPublicKey(getPublicKey(userId))
    except RuntimeError:
        print("\n\ERROR: No public key for provided id!\n\n")
        return None

    print("\n\n")
    recevied_secret_b85 = input("Please enter provided secret: ")
    received_secret_bytes = base64.b85decode(recevied_secret_b85)
    
    # Verify the received secret
    received_secret_bytes = base64.b85decode(recevied_secret_b85)
    recevied_signature_b85 = input("Please enter provided signature: ")
    recevied_signature_bytes = base64.b85decode(recevied_signature_b85)
    if(verify(received_secret_bytes,recevied_signature_bytes,publicKey) == False):
        print("\n----------\nERROR: Failed to verify signature!\n----------\n")
        return None

    # Calculate Shared Secret
    received_secret = bytesToPublicKey(received_secret_bytes)
    shared_secret, public_secret = completeECDH(active_private_key, received_secret)
    print("Session Initialized for user: "+ userId)
    print("\n\n")
    saveSessionKey(userId, shared_secret)

def sharePublicKeys(user_id):
    publicKey = publicKeyToBytes(getMyPublicKey(privateKeyFromPEM(getSigningKey())))
    print('\n----------------------------------')
    print("Share this public key (b85):\n" + base64.b85encode(publicKey).decode('ascii'))
    print('----------------------------------\n')
    recPublicKey = input("Please enter provided public key: ")
    storePublicKey(user_id, base64.b85decode(recPublicKey))

def main():
    try:
        signingkeyPEM = getSigningKey()
        signingKey = privateKeyFromPEM(signingkeyPEM)
    except RuntimeError:
        signingkey = generatePrivateKey()
        signingKeyPEM = privateKeyToPEM(signingkey)
        setSigningKey(signingKeyPEM)

    ActivePrivateSecret = None
    
    while(1):
        print('Available Functions:')
        print('----------------------------------')
        print('(1): Encrypt Message')
        print('(2): Decrypt Message')
        print('(3): (Re-)Initiate Session')
        print('(4): Accept Session Initiation')
        print('(5): Finalize Session Initiation')
        print('(6): Share Public Key')
        print('(7): Exit App')
        print('----------------------------------')

        chosen_mode = input('Choose function to perform: ')
        if(chosen_mode == '1'):
            user_id = input('Provide destination user_id: ')
            secret_message = input('Enter Secret Message: ')
            sendEncryptedMessage(user_id, secret_message)
            continue
        if(chosen_mode == '2'):
            user_id = input('Provide source user_id: ')
            encrypted_message = input('Enter Encrypted Message: ')
            iv = input('Enter IV: ')
            tag = input('Enter Tag: ')
            receiveEncryptedMessage(user_id, encrypted_message, iv, tag)
            continue
        if(chosen_mode == '3'):
            user_id = input('Provide destination user_id: ')
            ActivePrivateSecret = initializeSession(user_id)
            continue
        if(chosen_mode == '4'):
            user_id = input('Provide user_id: ')
            acceptSessionInit(user_id, None)
            continue
        if(chosen_mode == '5'):
            if ActivePrivateSecret == None:
                print('Function unavailable!')
                continue
            user_id = input('Provide user_id: ')
            acceptSessionInit(user_id, ActivePrivateSecret)
            continue
        if(chosen_mode == '6'):
            user_id = input('Provide user_id for shared user: ')
            sharePublicKeys(user_id)
            continue
        if(chosen_mode == '7'):
            print("Thanks for using your friendly E2E Application!")
            exit()
    
if __name__ == "__main__":
    main()