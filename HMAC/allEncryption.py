import os

from base64 import b64encode
from cryptography.hazmat.primitives.asymmetric import padding as a_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

key_size = 32
IVLength = 16

def fileEncryptMAC (filename):

    name, ext = os.path.splitext(filename)

    with open(filename, "rb") as someData:
        plaintext = someData.read()

    #pads the plaintext
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ENCKey = os.urandom(key_size)
    HMACKey = os.urandom(key_size)

    ciphertext, iv, tag = encryptMAC(ENCKey, HMACKey, padded_data)

    someData.close()
    return (ciphertext, iv, tag, ENCKey, HMACKey, ext)

def encryptMAC(ENCKey, HMACKey, plaintext):
    if len(HMACKey) < key_size:
        print("Error: the hash key must be greater than 256-bits in length")
        return ()

    ciphertext, iv = encrypt(ENCKey, plaintext)

    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    tag = h.finalize()

    return ciphertext, iv, tag

def encrypt(key, plaintext):
    if len(key) < key_size:
        print("Error: the key must be greater than 256-bits in length")
        return ()

    # Initializes the iv
    iv = os.urandom(IVLength)
    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        default_backend()
    ).encryptor()

    # Encrypt the plaintext and get the associated ciphertext.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (ciphertext, iv)

def RSAEncrypt(filepath, RSA_Publickey_filepath):
    C, IV, tag, ENCKey, HMACKey, ext = fileEncryptMAC(filepath)

    #load
    with open(RSA_Publickey_filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    combinedKey = ENCKey + HMACKey

    RSACipher = public_key.encrypt(
        combinedKey,
        a_padding.OAEP(
        mgf=a_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )

    return(RSACipher, C, IV, tag, ext)
