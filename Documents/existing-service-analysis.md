# Analysis of Existing Services

## Overview

There are several existing services that provide end-to-end encryption of messages and data. These services typically provide a client on either a mobile device, computer, or web app and a server that provides identification and establishment of channels with other users. In this analysis we will take a look at 2 existing services:

* Off-the-Record Messaging (OTR)
* Signal Messaging App

It is important to note that the protocol, or a modification thereof, that underpins Signal is also used by WhatsApp, Facebook Messenger, Skype, and Google Allo (defunct); as such, this analysis applies to these services as well. We will notably not be analyzing iMessage as the protocol is highly proprietary and in regular flux.

## Off-the-Record Messaging

OTR is a messaging service that was first released in 2004. The protocol was primarily implemented as a plug-in to existing messaging services, such as Pidgin or Kopete. The protocol combines symmetric encryption and the Diffie-Hellman key exchange to provide encryption with forward secrecy. The protocol does have the limitation that messages must be received in order for messages to be properly decrypted.

### Description of OTR Protocol

A full description of this protocol can be found here: https://otr.cypherpunks.ca/Protocol-v3-4.1.1.html

The protocol begins by either of two users requesting its use with an OTR query message. This stage does not involve encryption.

Next, the users execute a Diffie-Hellman key exchange with 320-bit random values with all exponentiations using 1536-bit primes. The exchange is heavily modified and includes the generation of multiple making multiple keys for encryption and message authentication codes, as well as sharing users public keys, which can later be used to authenticate. If all of the verifications succeeded, the two users now know each other's Diffie-Hellman public keys, and share the value s. Each user is assured that the shared secret is known by someone with access to the private key corresponding to the public key they received during the exchange.

During the actual data exchange, a new Diffie-Hellman secret is generated for every message exchange using key ids from most recent messages and acknowledged messages. From this an ecnrypting key and mac key are generated in a known way that can be produced by both users. Finally, the desired messaged is encrypted via AES-CTR and send with the previously described information.

While data messages are being exchanged, either user may run the Socialist Millionaire Protocol to detect impersonation or man-in-the-middle attacks. As above, all exponentiations are done modulo a particular 1536-bit prime, and g1 is a generator of that group. All sent values include zero-knowledge proofs that they were generated according to this protocol, as indicated in the detailed description below.

## Signal Messaging Protocol

Signal is a cross-platform centralized encrypted instant messaging service developed by the non-profit Signal Technology Foundation and Signal Messenger LLC. Signal's software is free and open-source; its mobile clients are published under the GPL-3.0-only license. Signal was initially released in 2014, though the protocol was initially released in the application TextSecure in 2010. Some sources indicate that TextSecure shares roots with the Off-The-Record- Messaging Protocol.

The Signal protocol combines the "Double Ratchet Algorithm", prekeys, and a triple Diffie-Hellman handshake. It uses Curve25519, AES-256, and HMAC-SHA256 as primitives. The protocol provides strong encryption, authentication, forward secrecy, and post compromise security.

### Description of Signal Protocol

In the Signal Protocol, users first execute a setup phase during registration, where they provide an ID to the Signal servers in the form of a phone number. During this registration, and a set of public keys, called the "pre-key bundle" is provided by the user to the server. 

From here, two users initiate a session by user A requesting the pre-key bundle for another  user (User B) from the server. User A may then combine the pre-key material for User B with their own to generate multiple keys: an ephemeral “ratchet” public key, a root key, chaining key, and message key. USer A then sends an encrypted message containing their ephemeral public key. User B may then derive shared secrets with pre-key bundle for User A received from the server.

Either user may then send messages to the other using a symmetric key ratchet, which involves executing a key derivation function to obtain a new symmetric with which they may send a new message. This occurs any time that users sends a message prior to receiving a message from the other user

For a user to send a message following receipt of a message from the other user, an  asymmetric ratchet must be performed, wherein the shared ephemeral public keys are changed using a key derivation function.
