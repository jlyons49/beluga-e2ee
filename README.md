# beluga

Beluga is an end-to-end encrypted messaging system that uses QR codes as the transport layer. Messages are encrypted on the local device and displayed as QR codes, which can then be transmitted over any channel — including untrusted networks, cameras, or photos — without compromising confidentiality. The receiving device scans the QR code and decrypts it locally.

Because encryption and decryption happen entirely offline, the system is resistant to network-level interception and requires no trusted server infrastructure.

## Cryptographic Design

- **Key exchange**: ECDH over SECP384R1 (P-384)
- **Session keys**: Derived with HKDF-SHA256
- **Encryption**: AES-256-GCM with zlib compression
- **Signatures**: ECDSA with SHA-256, used to authenticate ephemeral keys during session establishment
- **Key storage**: Password-protected encrypted database (AES-256-GCM)

Public keys should be exchanged in person to establish trust. Sessions can be re-established at any time.

---

## Implementations

### Python / Raspberry Pi (`Source/`)

The original implementation targets a Raspberry Pi as a dedicated offboard encryption device. The Pi handles all cryptographic operations and displays QR codes on an attached screen. A camera is used to scan incoming codes.

#### Python Requirements

- Python 3.7+
- [cryptography](https://pypi.org/project/cryptography/)
- [qrcode](https://pypi.org/project/qrcode/)
- [pyzbar](https://pypi.org/project/pyzbar/)
- [OpenCV 4.5.4](https://qengineering.eu/install-opencv-4.5-on-raspberry-pi-4.html)

#### Usage

From any directory, run `beluga`. The encrypted database is stored in the current working directory. First run will prompt you to create a password; subsequent runs require it to unlock the database.

---

### Android (`android/`)

A full Android port of the Python client, written in Kotlin. Provides the same cryptographic guarantees with a native mobile UI — using the phone's camera to scan incoming QR codes and the screen to display outgoing ones.

#### Android Requirements

- Android 8.0 (API 26) or higher
- Android Studio (to build from source)

#### Building

1. Open the `android/` directory in Android Studio
2. Allow Gradle to sync and download dependencies
3. Build and deploy to a device or emulator (`Run > Run 'app'`)

#### Security improvements over the Python client

| Area | Python | Android |
| --- | --- | --- |
| Password KDF | Single HKDF (fast, brute-forceable) | PBKDF2 (300k iterations) + HKDF |
| Salt | Hardcoded (`'girefub3'`) | Random 32-byte salt per installation, stored in Android Keystore-backed storage |
| Key storage | Encrypted JSON file | Same encrypted file format; salt protected by Android Keystore |

The QR wire format is identical between implementations, so a Python client and an Android device can exchange messages directly.

---

## Key Exchange Flow

1. Both parties exchange public keys in person by scanning each other's **Share Public Key** QR code.
2. Either party initiates a session by generating and displaying a **Session Init** QR code.
3. The other party scans it and displays their own **Session Init** reply.
4. After both sides have scanned, a shared session key is established via ECDH.
5. Encrypted messages are displayed as QR codes and scanned by the recipient.

---

## Documents

- [System Design Document](Documents/system-design.md)
- [Cryptographic Analysis of Other Systems](Documents/existing-service-analysis.md)
