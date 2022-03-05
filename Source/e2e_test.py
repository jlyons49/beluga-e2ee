from e2ejson import *
from e2ecrypto import *
import unittest
import random


class TestE2ECrypto(unittest.TestCase):
    def test_encrypt_then_decrypt(self):
        testString = str("This is just a test").encode('ASCII')
        key = os.urandom(32)
        encrypted, iv, tag = encrypt(testString, key)
        decrypted = decrypt(encrypted, iv, tag, key)
        self.assertEqual(testString, bytes(decrypted))
    
    def test_longencrypt(self):
        testString = str('').join(random.choices('123456789', k=32768)).encode('ASCII')
        key = os.urandom(32)
        encrypted, iv, tag = encrypt(testString, key)
        self.assertNotEqual(testString,encrypted)
        self.assertEqual(len(encrypted),32768)

    def test_decrypt_tag_failure(self):
        testString = str("This is just a test").encode('ASCII')
        key = os.urandom(32)
        encrypted, iv, tag = encrypt(testString, key)
        with self.assertRaises(RuntimeError):
            decrypt(encrypted, iv, b'0'*16, key)

    def test_decrypt_key_failure(self):
        testString = str("This is just a test").encode('ASCII')
        key = os.urandom(32)
        encrypted, iv, tag = encrypt(testString, key)
        with self.assertRaises(RuntimeError):
            decrypt(encrypted, iv, tag, bytearray(32))

    def test_sign_and_verify(self):
        testString = str('').join(random.choices('123456789', k=32768)).encode('ASCII')
        private_key = generatePrivateKey()
        public_key = private_key.public_key()
        signature = sign(testString,private_key)
        self.assertEqual(verify(testString,signature,public_key),True)
        
    def test_ECDH(self):
        private_key, public_key_1 = initiateECDH()
        shared_key_1, public_key_2 = completeECDH(None, public_key_1)
        shared_key_2, pkholder = completeECDH(private_key, public_key_2)
        self.assertEqual(shared_key_1,shared_key_2)

class TestE2EJson(unittest.TestCase):
    def test_save_and_load_session(self):
        id = str('').join(random.choices('123456789', k=16))
        key = os.urandom(32)
        saveSessionKey(id,key)
        key2 = getSessionKey(id)
        self.assertEqual(key, key2)
        removeSession(id)

    @unittest.skip('Skipping to prevent signing key destruction')
    def test_save_and_load_signingKey(self):
        key = base64.b85encode(os.urandom(384)).decode('ascii')
        setSigningKey(key)
        key2 = getSigningKey()
        self.assertEqual(key, key2)

    def test_save_and_load_publicKey(self):
        id = str('').join(random.choices('123456789', k=16))
        key = os.urandom(84)
        storePublicKey(id, key)
        key2 = getPublicKey(id)
        self.assertEqual(key, key2)
        removePublicKey(id)
