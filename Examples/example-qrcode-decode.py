import cv2
from pyzbar import pyzbar

image = cv2.imread('qrcode.png')
pbar = pyzbar.decode(image)

if pbar:
    print("Decoded message: \"" + pbar[0].data.decode() + "\"")
else :
    print("No QR code read from qrcode.png")
