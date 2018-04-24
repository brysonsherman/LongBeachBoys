from allEncryption import encryptDirectory
from allDecryption import decryptDirectory
from RSAKeyGen import RSAKeyGen
from keyPaths import keyPaths
from fileManagement import saveFileAsJSON, saveFile
import os

def main():
    #-----------------------------String test-----------------------------
    #print('\n\nBEGIN MYENCRYPT AND MYDECRYPT STRING TEST')
    #string_to_enc = "This is the test string to test out the encryption and decryption $
    #print('string to encrypt: ' + string_to_enc)
    #string_enc = encrypt.encrypt(string_key, string_to_enc, string_IV)

#    print('encrypted string: ' + string_enc.decode("utf-8"))
    #string_dec = decrypt.decrypt(string_enc, string_key, string_IV)
    #print('decrypted string: ' + string_dec.decode("ascii"))
    #print('END MYENCRYPT AND MYDECRYPT STRING TEST')
    #-----------------------------/String test----------------------------

    if(not os.path.isfile(keyPaths.pathToPrivateKey) and not os.path.isfile(kayPaths.pathToPublicKey)):
        RSAKeyGen(keyPaths.pathToPrivateKey, keyPaths.pathToPublicKey)
    workingDirectory = os.getcwd()
    filePathToDirectory = workingDirectory +"/TestDirectory"

    encryptDirectory(filePathToDirectory)

    decryptDirectory(filePathToDirectory)

if __name__ == '__main__':
    main()
