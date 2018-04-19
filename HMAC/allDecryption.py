
import os
from fileManagement import loadFileFromJSON, saveFile
from cryptography.hazmat.primitives.asymmetric import padding as a_padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from keyPaths import keyPaths

key_size = 32

def decryptDirectory(filepathToDirectory):
    fileList = os.listdir(filepathToDirectory)
    os.chdir(filepathToDirectory)

    for file in fileList:
         name, ext = os.path.splitext(file)
         plaintext, ext = RSADecrypt(file, keyPaths.pathToPrivateKey)
         saveFile(name, plaintext, ext)
         os.remove(file)

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

def fileDecrypt (filename):

    key, iv, ciphertext, ext = loadFileFromJSON(filename)

    plaintext = decrypt(ciphertext, key, iv)

    #unpads the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext) + unpadder.finalize()

    return (plaintext, ext)

def RSADecrypt(filepath, RSA_PrivateKeyPath):
    with open(RSA_PrivateKeyPath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password = None,
            backend = default_backend())

    ciphertext, RSAcipher, iv, tag, ext = loadFileFromJSON(filepath)
    combinedKey = private_key.decrypt(RSAcipher,
                              a_padding.OAEP(mgf=a_padding.MGF1(algorithm=hashes.SHA256()),
                              algorithm=hashes.SHA256(),
                              label=None)
                              )

    ENCKey = combinedKey[0:32]
    HMACKey = combinedKey[32:64]

    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
    h.update(ciphertext)
    h.verify(tag)
    plaintext = decrypt(ciphertext, ENCKey, iv)

    return plaintext, ext
