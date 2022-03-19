from e2ecrypto import *
from e2ejson import *
import cv2
import qrcode
import screeninfo
from pyzbar import pyzbar
import json
from PyQt5.QtWidgets import QApplication, QLabel, QGridLayout, QWidget
from PyQt5.QtGui import QPixmap

#TODO: remove dependencies by making a new module
import base64

screen = None
width, height = None, None
db = None

class Example(QWidget):

    def __init__(self):
        super().__init__()

        self.im = QPixmap("./qr.png")
        self.label = QLabel()
        self.label.setPixmap(self.im.scaledToWidth(420))

        self.grid = QGridLayout()
        self.grid.addWidget(self.label,1,1)
        self.setLayout(self.grid)

        self.setGeometry(0,0,480,480)
        self.setWindowTitle("PyQT show image")
        self.show()

def produceQRCode(qrmsg):
    qr = qrcode.QRCode(version=None,error_correction=qrcode.constants.ERROR_CORRECT_L,border=1,)
    qr.add_data(qrmsg)
    qr.make(fit=True)
    code = qr.make_image(fill_color="black", back_color="#dddddd")
    code.save("qr.png")
    if(screen != None):
        img = cv2.imread('qr.png')
        window_name = 'projector'
        cv2.namedWindow(window_name, cv2.WND_PROP_FULLSCREEN)
        cv2.moveWindow(window_name, screen.x - 1, screen.y - 1)
        cv2.setWindowProperty(window_name, cv2.WND_PROP_FULLSCREEN,
                            cv2.WINDOW_FULLSCREEN)
        img = cv2.resize(img,(height,height),interpolation=cv2.INTER_LINEAR)
        cv2.imshow(window_name, img)
        cv2.waitKey(0) # waits until a key is pressed
        cv2.destroyAllWindows() # destroys the window showing image
    else:
        app = QApplication(['0'])
        ex = Example()
        app.exec_()


# TODO: Move to other module
def sendEncryptedMessage(user_id, secret_message):
    #TODO: need to have a lookup for user to session
    session_id = user_id
    try:
        key = db.getSessionKey(session_id)
    except RuntimeError:
        print("No active session for user: " + user_id)
    encrypted_message_bytes, iv, tag = encrypt(bytes(secret_message,'ascii'), key)
    msg85= base64.b85encode(encrypted_message_bytes).decode('ascii')
    iv85 = base64.b85encode(iv).decode('ascii')
    tag85 = base64.b85encode(tag).decode('ascii')
    msgJSON = {"mode":1,"iv":iv85, "ct":msg85, "tag":tag85}
    qrmsg = json.dumps(msgJSON)
    produceQRCode(qrmsg)

# TODO: Move to other module
def receiveEncryptedMessage(user_id, encrypted_message, iv, tag):
    #TODO: need to have a lookup for user to session
    session_id = user_id
    try:
        key = db.getSessionKey(session_id)
    except RuntimeError:
        print("No active session for user: " + user_id)
    encrypted_message_bytes = base64.b85decode(encrypted_message)
    message_bytes = decrypt(encrypted_message_bytes, base64.b85decode(iv), base64.b85decode(tag), key)
    print("\n\n")
    print("This is your secret message:\n----------\n" + message_bytes.decode('ASCII'))
    print("\n\n")

def receiveQRCode(ActivePrivateSecret):
    user_id = input("Please specify source user id: ")
    data = cameraCapture()
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
    if mode == 6:
        receivePublicKey(user_id, data['publickey'])
        return
    return

# TODO: Move to other module
def initializeSession(userId):
    try:
        publicKey = bytesToPublicKey(db.getPublicKey(userId))
    except RuntimeError:
        print("\n\ERROR: No public key for provided id!\n\n")
        return None
    PrivateSecret, PublicSecret = initiateECDH()
    public_secret_bytes = publicKeyToBytes(PublicSecret)
    signature = sign(public_secret_bytes,privateKeyFromPEM(db.getSigningKey()))
    ps85 = base64.b85encode(public_secret_bytes).decode('ascii')
    sig85 = base64.b85encode(signature).decode('ascii')
    msgJSON = {"mode":3,"sec":ps85, "sig":sig85}
    qrmsg = json.dumps(msgJSON)
    produceQRCode(qrmsg)
    return PrivateSecret

def acceptSessionInit(userId, active_private_secret, received_secret_b85, recevied_signature_b85):
    try:
        publicKey = bytesToPublicKey(db.getPublicKey(userId))
    except RuntimeError:
        print("\n\ERROR: No public key for provided id!\n\n")
        return None

    new_initiation = False

    if(active_private_secret == None):
        active_private_secret, PublicSecret = initiateECDH()
        new_initiation = True
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
    db.saveSessionKey(userId, shared_secret)

    # Provide new public secret if new session initiation
    if(new_initiation):
        public_secret_bytes = publicKeyToBytes(PublicSecret)
        signature = sign(public_secret_bytes,privateKeyFromPEM(db.getSigningKey()))
        ps85 = base64.b85encode(public_secret_bytes).decode('ascii')
        sig85 = base64.b85encode(signature).decode('ascii')
        msgJSON = {"mode":3,"sec":ps85, "sig":sig85}
        qrmsg = json.dumps(msgJSON)
        produceQRCode(qrmsg)
    

def sharePublicKeys():
    publicKey = publicKeyToBytes(getMyPublicKey(privateKeyFromPEM(db.getSigningKey())))
    publicKey_85 = base64.b85encode(publicKey).decode('ascii')
    msgJSON = {"mode":6,"publickey":publicKey_85}
    qrmsg = json.dumps(msgJSON)
    produceQRCode(qrmsg)

def receivePublicKey(user_id, received_pub_key_b85):
    public_key = base64.b85decode(received_pub_key_b85)
    db.storePublicKey(user_id, public_key)

def cameraCapture():
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
        h = int(img.shape[0]*.6)
        w = int(img.shape[1]*.6)
        img = cv2.resize(img,(w,h),interpolation=cv2.INTER_LINEAR)
        img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        pbar = pyzbar.decode(img)
        if pbar:
            decoded = pbar[0].data.decode()
            data = json.loads(decoded)
            print("data found: ", data)
            x, y, qrw, qrh = pbar[0].rect.left, pbar[0].rect.top, pbar[0].rect.width, pbar[0].rect.height
            cv2.rectangle(img, (x,y),(x+qrw, y+qrh),(255, 0, 0), 8)
        img = cv2.resize(img,(int(w/4),int(h/4)),interpolation=cv2.INTER_LINEAR)
        cv2.imshow("code detector", img)
        if(cv2.waitKey(1) == ord("q") or data):
            break
    # free camera object and exit
    cap.release()
    cv2.destroyAllWindows()
    return data


def main():
    global screen, width, height
    global db

    db = jsonDatabase()

    try:
        signingkeyPEM = db.getSigningKey()
        signingKey = privateKeyFromPEM(signingkeyPEM)
    except RuntimeError:
        signingkey = generatePrivateKey()
        signingKeyPEM = privateKeyToPEM(signingkey)
        db.setSigningKey(signingKeyPEM)

    ActivePrivateSecret = None

    # get the size of the screen
    
    try:
        screen = screeninfo.get_monitors()[0]
        width, height = screen.width, screen.height
    except:
        print("No screen available!")
    
    while(1):
        print('Available Functions:')
        print('----------------------------------')
        print('(1): Receive a QR Code')
        print('(2): Encrypt Message')
        print('(3): (Re-)Initiate Session')
        print('(4): Share Public Key')
        print('(5): Exit App')
        print('----------------------------------')

        chosen_mode = input('Choose function to perform: ')
        if(chosen_mode == '1'):
            receiveQRCode(ActivePrivateSecret)
            continue
        elif(chosen_mode == '2'):
            user_id = input('Provide destination user_id: ')
            secret_message = input('Enter Secret Message: ')
            sendEncryptedMessage(user_id, secret_message)
            continue
        elif(chosen_mode == '3'):
            user_id = input('Provide destination user_id: ')
            ActivePrivateSecret = initializeSession(user_id)
            continue
        elif(chosen_mode == '4'):
            sharePublicKeys()
            continue
        elif(chosen_mode == '5'):
            print("Thanks for using your friendly E2E Application!")
            exit()
        else:
            print("Invalid Mode!")
            continue
    
if __name__ == "__main__":
    main()