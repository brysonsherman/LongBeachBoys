Last login: Thu Mar 15 11:42:52 on ttys002
dhcp-39-14-34:~ lukecjm$ ssh webserver
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Mar 15 20:17:04 UTC 2018

  System load:  0.0               Processes:           124
  Usage of /:   37.8% of 7.74GB   Users logged in:     1
  Memory usage: 37%               IP address for eth0: 172.31.34.193
  Swap usage:   0%

  Graph this data and manage this system at:
    https://landscape.canonical.com/

  Get cloud support with Ubuntu Advantage Cloud Guest:
    http://www.ubuntu.com/business/services/cloud

19 packages can be updated.
10 updates are security updates.


Last login: Thu Mar 15 18:59:57 2018 from 134.139.206.52
ubuntu@ip-172-31-34-193:~$ cd PythonVirtualEnv/bin
ubuntu@ip-172-31-34-193:~/PythonVirtualEnv/bin$ ls
activate       easy_install-3.5  FinalEncryption.py  pip3
activate.csh   encrypt.py        main.py             pip3.5
activate.fish  encrypt.pyc       main.pyc            __pycache__
decrypted.txt  fileDecrypt.py    MyEncryption.py     python
decrypt.py     fileDecrypt.pyc   MyEncryption.pyc    python3
decrypt.pyc    fileEncrypt.py    P51.jpg             toDecrypt.json
easy_install   fileEncrypt.pyc   pip                 toEncrypt.txt
ubuntu@ip-172-31-34-193:~/PythonVirtualEnv/bin$ nano FinalEncryption.py








  GNU nano 2.5.3             File: FinalEncryption.py                                  

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
    #string_to_enc = "This is the test string to test out the encryption and decryptio$
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
