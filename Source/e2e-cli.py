from e2eimplementation import *
import json

#TODO: remove dependencies by making a new module
import base64

def printEncryptedMessage(output_json):
    data = json.loads(output_json)
    encrypted_message_b85 = data['ct']
    iv_b85 = data['iv']
    tag_b85 = data['tag']
    print('\n----------------------------------')
    print("This is your encrypted message (b85):\n" + encrypted_message_b85)
    print("This is your iv (b85):\n" + iv_b85)
    print("This is your tag (b85):\n" + tag_b85)
    print('----------------------------------\n')
    input("Press any key to continue...")

def printSessionInitiation(output_json):
    data = json.loads(output_json)
    secret_b85 = data['sec']
    signature_b85 = data['sig']
    print('\n----------------------------------')
    print("Share this public secret (b85):\n" + secret_b85)
    print("Share this signature (b85):\n" + signature_b85)
    print('----------------------------------\n')
    input("Press any key to continue...")

def printPublicKey(output_json):
    data = json.loads(output_json)
    public_key_b85 = data['publickey']
    print('\n----------------------------------')
    print("Share this public key (b85):\n" + public_key_b85)
    print('----------------------------------\n')
    input("Press any key to continue...")

def main():

    implementation = e2eSystem()
    
    while(1):
        print('Available Functions:')
        print('----------------------------------')
        print('(1): Encrypt Message')
        print('(2): Decrypt Message')
        print('(3): (Re-)Initiate Session')
        print('(4): Accept Session Initiation')
        print('(5): Share Public Key')
        print('(6): Exit App')
        print('----------------------------------')

        chosen_mode = input('Choose function to perform: ')
        if(chosen_mode == '1'):
            user_id = input('Provide destination user_id: ')
            secret_message = input('Enter Secret Message: ')
            result_json = implementation.sendEncryptedMessage(user_id, secret_message)
            printEncryptedMessage(result_json)
            continue
        if(chosen_mode == '2'):
            user_id = input('Provide source user_id: ')
            encrypted_message = input('Enter Encrypted Message: ')
            iv = input('Enter IV: ')
            tag = input('Enter Tag: ')
            result_json = implementation.receiveEncryptedMessage(user_id, encrypted_message, iv, tag)
            print("\n\n")
            print("This is your secret message:\n----------\n" + result_json)
            print("\n\n")
            continue
        if(chosen_mode == '3'):
            user_id = input('Provide destination user_id: ')
            result_json = implementation.initializeSession(user_id)
            printSessionInitiation(result_json)
            continue
        if(chosen_mode == '4'):
            user_id = input('Provide user_id: ')
            received_secret = input('Enter Received Secret (b85): ')
            received_signature = input('Enter Received Signature (b85): ')
            result_json = implementation.acceptSessionInit(user_id, received_secret, received_signature)
            if result_json != None:
                printSessionInitiation(result_json)
            continue
        if(chosen_mode == '5'):
            result_json = implementation.sharePublicKeys()
            printPublicKey(result_json)
            continue
        if(chosen_mode == '6'):
            print("Thanks for using your friendly E2E Application!")
            exit()
    
if __name__ == "__main__":
    main()