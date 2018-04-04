from allEncryption import RSAEncrypt
from RSAKeyGen import RSAKeyGen
from allDecryption import RSADecrypt
from fileManagement import saveFileAsJSON, saveFile
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

    RSAKeyGen('.ssh/rsaKey.pem', '.ssh/rsaKey.pem.pub')
    RSAcipher, ciphertext, iv, tag, ext = RSAEncrypt('P51.jpg', '.ssh/rsaKey.pem.pub')
    saveFileAsJSON('toDecrypt.json', ciphertext, iv, RSAcipher, tag,  ext)

    plaintext, ext = RSADecrypt('toDecrypt.json', '.ssh/rsaKey.pem')
    saveFile('P51decrypted', plaintext, ext)
if __name__ == '__main__':
    main()
