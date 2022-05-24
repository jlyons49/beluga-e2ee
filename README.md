# beluga

This is the repository for an End-to-End Encrypted messaging solution targeting a raspberry pi as an offboard encryption device. The system will produce QR codes to a display attached to the raspberry pi which can be sent over any channel without compromising data confidentiality.

## Usage Requirements

* A compute device with a screen and a camera
* Python 3.7 (May be backwards/forwads compatible but untested)
* Python modules:
  * [Cryptography](https://pypi.org/project/cryptography/)
  * [qrcode](https://pypi.org/project/qrcode/)
  * [pyzbar](https://pypi.org/project/pyzbar/)
* [OpenCV 4.5.4](https://qengineering.eu/install-opencv-4.5-on-raspberry-pi-4.html)

## Usage

From any directory, call `beluga`. The relavant database will be stored at the location local to where the call was made. First use will require creation of a password; subsequent uses will require this password to be entered prior to access of the database. Establishment of trusted public keys is recommended to take place in-person. Sessions should be re-established regularly.

## Documents

* [System Design Document](https://github.gatech.edu/jlyons3/e2e-system/blob/63914044cc1f510431c9c68bf7e5050aa5f48d9d/Documents/system-design.md)
* [Cryptographic Analysis of Other Systems](https://github.gatech.edu/jlyons3/e2e-system/blob/c6f067ad5d362520de551f16754d2006916249e3/Documents/existing-service-analysis.md)
