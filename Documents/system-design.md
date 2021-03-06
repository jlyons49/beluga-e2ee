# System Design Document for End-To-End Encryption System

## Introduction

## Overview

The implementation of this system will utilize a commercially available single board computer (SBC) to execute encryption of messages and produce machine-readable images (such as QR codes) encoding those messages. The encoding of data in a visual medium acts as a one-way data diode, allowing the SBC to execute in an air-gapped environment. For encryption, I will identify particular algorithms that preserve some level of ease-of-use while optimizing for overall security. The encryption scheme will include similar overall steps to existing E2E services, including initial credential generation, session authentication and establishment, and ciphertext generation and presentation. The system will leverage OpenSSL as the encryption library.

Requirements for this system can be found in the [System Requirements Document](https://github.gatech.edu/jlyons3/e2e-system/blob/ba8676dcf035279858c53cb4489d1ad1ec961d3e/Documents/system-requirements.md)

## System Architecture

### System Components

The system will consist of two primary components, the Host Device and the Communication Channel Device.

#### __Host Device__

The system will utilize a modern SBC for the host of the implementation. This device will provide the following functions cryptographic functions:

* User Input
* Image Input
* Cryptographic Functions

At present, the target device for this component is a Raspberry Pi 4 with the following peripherals: Screen, Camera, Keyboard.

#### __Communication Channel Device__

The system will be agnostic to the hardware used to implement the communications hardware; however, for simplicity, the system will assume this hardware has the capability to send and receive images.

### System Software

All software developed for this system will target the Host Device. At present, the specification for the software environment is as such:

* Operating System: Raspbian Buster
* Execution Environment: Python 3.10
* Other dependencies: [opencv-python](https://pypi.org/project/opencv-python/), [qrcode 7.3.1](https://pypi.org/project/qrcode/)

### System Interfaces

The system interface will primarily consist of the screen, camera, and keyboard. The screen will provide a GUI to the user which will be commanded by USB keyboard. The camera will be used to scan incoming visual representations of messages.

## System Functionality

### System Usage

Use of the system will follow this scheme:

1. User A will generate a public-private key pair with their host device.
2. User B will generate a public-private key pair with their host device..
3. User's A and B will share their public keys in-person or via a known secure channel.
    1. Each user's host device will display their public key via visual medium.
    1. Each user will scan the other user's public key with their own host device and store the credential.
4. User A will generate a session establishment request with the other user.
    1. User A will generate the request as a visual representation and transmit to other user.
    2. User B will scan the request and respond with a session establishment confirmation message.
    3. User A will receive and scan the session establishment confirmation message.
    4. If the session establishment confirmation message is authenticated, User A's host device will generate a session establishment final message containing a generated shared secret.
5. The session is now established and User's A and B may exchange messages utilizing the session's established shared secret.
    1. User A will input a message into the Host Device.
    2. The Host Device will encrypt the message with the session's shared secret and display a visual representation.
    3. User A will transmit the visual representation via the Communication Channel Device.
    4. User B will receive via their Communication Channel Device and scan the visual representation with their Host Device.
    5. User B's Host Device will decrypt the with the session's shared secret and display a plain text representation.
6. At any time, User A or B may request a new session establishment.
    1. The system will automatically perform this action on a configurable timeout.

### System Deployment

The system will be deployed via a preconfigured image which includes all software and tools necessary to utilize the system.

## Cryptographic Implementation

### Crypto Overview

This system seeks to maximize confidentiality of messages while maintaining an acceptable level of ease-of-use. It is important that the system be usable.

For maximizing confidentiality, the first layer of implementation will require a strong symmetric cryptography scheme. Ideally, this scheme will additionally provide integtriy guarantees. As such, [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) with 256-bit key will be utilized in this system. While this strong symmetric cryptography provides good encryption, its exclusive use would result in a lack of [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy). In order to achieve forward secrecy, the system will need to establish sessions with a new symmetric key for each session. This session establishment must utilize some for of secret agreement, such as the [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange); however, the base DH key exchange does not inherently provide forward secrecy, nor does it guarantee autheticity of the parties to each other. To resolve the first issue, a new private secret must be chosen for each session establishment; this is referred to as the ephemeral variant of DH. To resolve the issue of authenticity, a signing algorithm must be applied in addition to DH. A scheme such as [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) or [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) can provide this capability.

Every data transmission requires manual intervention by a user, so any scheme requiring a high number of transactions for use would be prohibitive, eliminating the available of some complex schemes. Performance in this regard can be improved eliminating some exchanges that are utilized in other systems at the expense of optimal security. For example, the system may set static agreements on the precise crypto schemes to be used or the particular curves to be used for elliptic curve components.

### Crypto Suite

The crypto suite to be utilized in this system consists of the following:

* Session Authentication: Elliptic Curve Digital Signature Algorithm (ECDSA)
* Session Secret Establishment: Elliptic Curve Diffie-Hellman, Ephemeral (ECDHE)
* Session Encryption and Integrity: AES-256, Galois Counter Mode (AES-GCM)
