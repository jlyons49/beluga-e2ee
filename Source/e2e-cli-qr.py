from e2eimplementation import *
import cv2
import qrcode
import screeninfo
from pyzbar import pyzbar
import json
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

screen = None
width, height = None, None

class QRDisplay(QWidget):

    def __init__(self):
        super().__init__()

        self.label = QLabel("Provide this to other user:")

        self.im = QPixmap("./qr.png")
        self.image = QLabel()
        self.image.setPixmap(self.im.scaledToHeight(440))

        self.verticallayout = QVBoxLayout()
        self.verticallayout.setAlignment(Qt.AlignHCenter)
        self.verticallayout.addWidget(self.label)
        self.verticallayout.addWidget(self.image)
        self.setLayout(self.verticallayout)

        self.setWindowTitle("QR Code Display")
        self.showMaximized()

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
        return
    app = QApplication(['0'])
    ex = QRDisplay()
    app.exec_()

def receiveQRCode(implementation):
    user_id = input("Please specify source user id: ")
    data = cameraCapture()
    try:
        mode = data['mode']
    except:
        print("Invalid QR Code!")
        return
    if mode == 1:
        result = implementation.receiveEncryptedMessage(user_id, data['ct'],data['iv'],data['tag'])
        print("\n\n")
        print("This is your secret message:\n----------\n" + result)
        print("\n\n")
        return
    if mode == 3:
        result_json = implementation.acceptSessionInit(user_id, data['sec'], data['sig'])
        if result_json != None:
            produceQRCode(result_json)
        return
    if mode == 6:
        implementation.receivePublicKey(user_id, data['publickey'])
        return
    return

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

    opened = False
    count = 0

    while not opened or count>3:
        password = input("Please provide system password: ")
        count = count + 1
        try:
            implementation = e2eSystem(password)
        except RuntimeError:
            print("Password failure or corrupted database!")
            print("Remove database.json if password unrecoverable!")
            continue
        opened = True
    password = ""

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
            receiveQRCode(implementation)
            continue
        elif(chosen_mode == '2'):
            user_id = input('Provide destination user_id: ')
            secret_message = input('Enter Secret Message: ')
            encrypted_message_json = implementation.sendEncryptedMessage(user_id, secret_message)
            produceQRCode(encrypted_message_json)
            continue
        elif(chosen_mode == '3'):
            user_id = input('Provide destination user_id: ')
            session_init_json = implementation.initializeSession(user_id)
            if session_init_json != None:
                produceQRCode(session_init_json)
            continue
        elif(chosen_mode == '4'):
            public_key_json = implementation.sharePublicKeys()
            produceQRCode(public_key_json)
            continue
        elif(chosen_mode == '5'):
            print("Thanks for using your friendly E2E Application!")
            exit()
        else:
            print("Invalid Mode!")
            continue
    
if __name__ == "__main__":
    main()