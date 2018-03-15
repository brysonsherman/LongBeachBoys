import os
import base64
import json

from cryptography.hazmat.primitives import padding
from base64 import b64decode
from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

key_size = 32
IVLength = 16

def encrypt(key, plaintext: bytes, iv):
    if len(key) < key_size:
        print("Error: the key must be greater than 256-bits in length")
        return ()

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        default_backend()
    ).encryptor()

    # Encrypt the plaintext and get the associated ciphertext.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext

def decrypt(ciphertext,key, iv):
    if len(key) < key_size:
        print("Error: The key must be 256-bits in length.")
        return ()

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        default_backend()
    ).decryptor()

    # Decrypt the plaintext and get the associated ciphertext.
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

def fileEncrypt (filename, key, iv, storeToFile):

    name, ext = os.path.splitext(filename)

    with open(filename, "rb") as someData:
        plaintext = someData.read()

    #pads the plaintext
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encrypt(key, padded_data, iv)

    data = {
        'IV': b64encode(iv).decode('utf-8'),
        'Key': b64encode(key).decode('utf-8'),
        'Text': b64encode(ciphertext).decode('utf-8'),
        'Extension': ext
        }

    with open(storeToFile, 'w') as outFile:
        json.dump(data, outFile)
    outFile.close()

    return ()

def fileDecrypt (filename, storeToFile):

    with open(filename, 'r') as json_file:
        data = json.load(json_file)

    key = b64decode(data["Key"])
    iv = b64decode(data["IV"])
    ciphertext = b64decode(data["Text"])
    ext = data["Extension"]

    plaintext = decrypt(ciphertext, key, iv)

    #unpads the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext) + unpadder.finalize()

    with open(storeToFile, "wb") as outFile:
        outFile.write(plaintext)
        outFile.close()

    return ()

def main():
    #-----------------------------String test-----------------------------
    #print('\n\nBEGIN MYENCRYPT AND MYDECRYPT STRING TEST')
    string_key = os.urandom(key_size)
    string_IV = os.urandom(IVLength)
    #string_to_enc = "This is the test string to test out the encryption and decryption $
    #print('string to encrypt: ' + string_to_enc)
    #string_enc = encrypt.encrypt(string_key, string_to_enc, string_IV)
#    print('encrypted string: ' + string_enc.decode("utf-8"))
    #string_dec = decrypt.decrypt(string_enc, string_key, string_IV)
    #print('decrypted string: ' + string_dec.decode("ascii"))
    #print('END MYENCRYPT AND MYDECRYPT STRING TEST')
    #-----------------------------/String test----------------------------

    fileEncrypt('P51.jpg', string_key, string_IV, 'toDecrypt.json')

    fileDecrypt('toDecrypt.json', 'P51decrypt.jpg')
if __name__ == '__main__':
    main()
