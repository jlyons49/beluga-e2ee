from e2ecrypto import *
from e2ejson import *
import cv2
import qrcode
import screeninfo
from pyzbar import pyzbar
import json

#TODO: remove dependencies by making a new module
import base64

screen = None
width, height = None, None

def produceQRCode(qrmsg):
    qr = qrcode.QRCode(version=None,error_correction=qrcode.constants.ERROR_CORRECT_L,border=1,)
    qr.add_data(qrmsg)
    qr.make(fit=True)
    code = qr.make_image(fill_color="black", back_color="#dddddd")
    code.save("testqr.png")
    img = cv2.imread('testqr.png')
    window_name = 'projector'
    cv2.namedWindow(window_name, cv2.WND_PROP_FULLSCREEN)
    cv2.moveWindow(window_name, screen.x - 1, screen.y - 1)
    cv2.setWindowProperty(window_name, cv2.WND_PROP_FULLSCREEN,
                          cv2.WINDOW_FULLSCREEN)
    img = cv2.resize(img,(height,height),interpolation=cv2.INTER_LINEAR)
    cv2.imshow(window_name, img)
    cv2.waitKey(0) # waits until a key is pressed
    cv2.destroyAllWindows() # destroys the window showing image

# TODO: Move to other module
def sendEncryptedMessage(user_id, secret_message):
    #TODO: need to have a lookup for user to session
    session_id = user_id
    try:
        key = getSessionKey(session_id)
    except RuntimeError:
        print("No active session for user: " + user_id)
    encrypted_message_bytes, iv, tag = encrypt(bytes(secret_message,'ascii'), key)
    msg85= base64.b85encode(encrypted_message_bytes).decode('ascii')
    iv85 = base64.b85encode(iv).decode('ascii')
    tag85 = base64.b85encode(tag).decode('ascii')
    print('\n----------------------------------')
    print("This is your encrypted message (b85):\n" + base64.b85encode(encrypted_message_bytes).decode('ascii'))
    print("This is your iv (b85):\n" + base64.b85encode(iv).decode('ascii'))
    print("This is your tag (b85):\n" + base64.b85encode(tag).decode('ascii'))
    print('----------------------------------\n')
    msgJSON = {"mode":1,"iv":iv85, "ct":msg85, "tag":tag85}
    qrmsg = json.dumps(msgJSON)
    produceQRCode(qrmsg)

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

def receiveQRCode(ActivePrivateSecret):
    user_id = input("Please specify source user id: ")
    data = camTest()
    try:
        mode = data['mode']
    except:
        print("Invalid QR Code!")
        return
    if mode == 1:
        receiveEncryptedMessage(user_id, data['ct'],data['iv'],data['tag'])
        return
    if mode == 3:
        acceptSessionInit(user_id, ActivePrivateSecret, data['sec'], data['sig'])
        return
    return

def receiveEncryptedQRCode(user_id):
    try:
        key = getSessionKey(user_id)
    except RuntimeError:
        print("No active session for user: " + user_id)
    data = camTest()
    tag = base64.b85decode(data['tag'])
    iv = base64.b85decode(data['iv'])
    msg = base64.b85decode(data['ct'])
    message_bytes = decrypt(msg, iv, tag, key)
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
    ps85 = base64.b85encode(public_secret_bytes).decode('ascii')
    sig85 = base64.b85encode(signature).decode('ascii')
    print("\n\n")
    print("Please provide this public secret to the other user:\n----------\n" + ps85)
    print("\nPlease provide this signature to the other user:\n----------\n" + sig85)
    print("\n\n")
    msgJSON = {"mode":3,"sec":ps85, "sig":sig85}
    qrmsg = json.dumps(msgJSON)
    produceQRCode(qrmsg)
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

def acceptSessionInit(userId, active_private_secret, received_secret_b85, recevied_signature_b85):
    try:
        publicKey = bytesToPublicKey(getPublicKey(userId))
    except RuntimeError:
        print("\n\ERROR: No public key for provided id!\n\n")
        return None

    if(active_private_secret == None):
        active_private_secret, PublicSecret = initiateECDH()
    else:
        PublicSecret = getMyPublicKey(active_private_secret)

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
    shared_secret, _ = completeECDH(active_private_secret, received_secret)
    print("Session Initialized for user: "+ userId)
    print("\n\n")
    public_secret_bytes = publicKeyToBytes(PublicSecret)
    signature = sign(public_secret_bytes,privateKeyFromPEM(getSigningKey()))
    ps85 = base64.b85encode(public_secret_bytes).decode('ascii')
    sig85 = base64.b85encode(signature).decode('ascii')
    msgJSON = {"mode":3,"sec":ps85, "sig":sig85}
    qrmsg = json.dumps(msgJSON)
    produceQRCode(qrmsg)
    saveSessionKey(userId, shared_secret)

def sharePublicKeys(user_id):
    publicKey = publicKeyToBytes(getMyPublicKey(privateKeyFromPEM(getSigningKey())))
    print('\n----------------------------------')
    print("Share this public key (b85):\n" + base64.b85encode(publicKey).decode('ascii'))
    print('----------------------------------\n')
    recPublicKey = input("Please enter provided public key: ")
    storePublicKey(user_id, base64.b85decode(recPublicKey))

def camTest():
    # set up camera object
    cap = cv2.VideoCapture(0)
    detector = cv2.QRCodeDetector()
    cap.set(11,1.)
    cap.set(12,1.)

    data = None
    pbar = False

    while True:
        # get the image
        _, img = cap.read()
        img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        minx, maxx, miny, maxy = None, None, None, None
        h = int(img.shape[0]*.5)
        w = int(img.shape[1]*.5)
        img = cv2.resize(img,(w,h),interpolation=cv2.INTER_LINEAR)
        dataq, bbox, _ = detector.detectAndDecode(img)
        data = False
        if(bbox is not None):
            for i in range(len(bbox[0])):
                x1 = int(bbox[0][i][0])
                y1 = int(bbox[0][i][1])
                x2 = int(bbox[0][(i+1) % len(bbox[0])][0])
                y2 = int(bbox[0][(i+1) % len(bbox[0])][1])
                cv2.line(img,(x1,y1),(x2,y2),color=(0,255, 0), thickness=5)
        pbar = pyzbar.decode(img)
        img = cv2.resize(img,(int(w/4),int(h/4)),interpolation=cv2.INTER_LINEAR)
        if pbar:
            decoded = pbar[0].data.decode()
            data = json.loads(decoded)
            print("data found: ", data)
        cv2.imshow("code detector", img)
        if(cv2.waitKey(1) == ord("q") or data):
            break
    # free camera object and exit
    cap.release()
    cv2.destroyAllWindows()
    return data


def main():
    try:
        signingkeyPEM = getSigningKey()
        signingKey = privateKeyFromPEM(signingkeyPEM)
    except RuntimeError:
        signingkey = generatePrivateKey()
        signingKeyPEM = privateKeyToPEM(signingkey)
        setSigningKey(signingKeyPEM)

    ActivePrivateSecret = None

    # get the size of the screen
    global screen, width, height
    try:
        screen = screeninfo.get_monitors()[0]
        width, height = screen.width, screen.height
    except:
        print("No screen available!")
    
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
        print('(8): Receive a QR Code')
        print('----------------------------------')

        chosen_mode = input('Choose function to perform: ')
        if(chosen_mode == '1'):
            user_id = input('Provide destination user_id: ')
            secret_message = input('Enter Secret Message: ')
            sendEncryptedMessage(user_id, secret_message)
            continue
        if(chosen_mode == '2'):
            user_id = input('Provide source user_id: ')
            # encrypted_message = input('Enter Encrypted Message: ')
            # iv = input('Enter IV: ')
            # tag = input('Enter Tag: ')
            #receiveEncryptedMessage(user_id, encrypted_message, iv, tag)
            receiveEncryptedQRCode(user_id)
            continue
        if(chosen_mode == '3'):
            user_id = input('Provide destination user_id: ')
            ActivePrivateSecret = initializeSession(user_id)
            continue
        if(chosen_mode == '4'):
            user_id = input('Provide user_id: ')
            acceptSessionInit(user_id, None, None,None)
            continue
        if(chosen_mode == '5'):
            if ActivePrivateSecret == None:
                print('Function unavailable!')
                continue
            user_id = input('Provide user_id: ')
            acceptSessionInit(user_id, ActivePrivateSecret,None,None)
            continue
        if(chosen_mode == '6'):
            user_id = input('Provide user_id for shared user: ')
            sharePublicKeys(user_id)
            continue
        if(chosen_mode == '7'):
            print("Thanks for using your friendly E2E Application!")
            exit()
        if(chosen_mode == '8'):
            receiveQRCode(ActivePrivateSecret)
            continue
    
if __name__ == "__main__":
    main()