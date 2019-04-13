#!/usr/bin/python3

#Version 1.0

#Created by: Robert O'Connor
#Class: NTS370
#This program will encrypt either a file
#or text in various encryption methods.



#What is left to do.
#File Encryption


import os
import random
import struct
import base64
import sys
import hashlib
import cryptography
from cryptography.fernet import Fernet

print('''
  ______                             _
 |  ____|                           | |
 | |__   _ __   ___ _ __ _   _ _ __ | |_ ___ _ __
 |  __| | '_ \ / __| '__| | | | '_ \| __/ _ \ '__|
 | |____| | | | (__| |  | |_| | |_) | ||  __/ |
 |______|_| |_|\___|_|   \__, | .__/ \__\___|_|
                          __/ | |
                         |___/|_|
                         ''')

print('==================================================')
print('               Welcome to Encrypter.')
print('==================================================')

def fileMenu():
    fileChoice = input('''
    =========================================
    Now choose the method of text encryption.
    =========================================

    1. Symmetric Encryption
    2. Blowfish
    3. Twofish
    4. RSA
    5. Quit\n
    ''')

    if fileChoice == '1':
        symmetricEncryption()
    #elif fileChoice == '2':
        #3DESEncryption
    #elif fileChoice == '3':
        #TwofishEncryption
    #elif fileChoice == '4':
        #RSAEncryption
    elif fileChoice == '5':
        print('Exiting program.')
        sys.exit(0)
    else:
        print('You must select what is in the menu.')
        fileMenu()



#Encrypting the file
def symmetricEncryption():
    encryptionKey = Fernet.generate_key()

    input_file = input("Enter the path of your file: ")
    assert os.path.exists(input_file), "[+] There is no file in that location."
    f = open(input_file, 'r+')
    print('[+] File Exists')
    f.close()
    output_file = 'encryptedFile.encrypted'

    with open(input_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(encryptionKey)
    encrypted = fernet.encrypt(data)

    with open(output_file, 'wb') as f:
        f.write(encrypted)

    print('\n[+] The key for the encrypted file is in single quotes: ', encryptionKey)
    print('\nIt is recommended you keep the key somewhere safe because that')
    print('is the only way to decrypt the file.\n')
    print('[+] File has been encrypted')

def textMenu():
    textChoice = input('''
    =========================================
    Now choose the method of text encryption.
    =========================================

    1. MD5 Hash
    2. SHA256 Hash
    3. Base64
    4. Quit\n
    ''')

    if textChoice == '1':
        MD5Encryption()
    elif textChoice == '2':
        SHA256Encryption()
    elif textChoice == '3':
        base64Encryption()
    elif textChoice == '4':
        print('Exiting program.')
        sys.exit(0)
    else:
        print('You must select what is in the menu.')
        textMenu()

#MD5 Hash based encryption
def MD5Encryption():
    textEncryption = input('Enter text to be encrypted.\n')
    #Encodes the string to MD5
    MD5Encrypt = hashlib.md5(textEncryption.encode())
    MD5Digest = MD5Encrypt.hexdigest()
    print("[+] MD5 Encoded String: ", MD5Digest)

#SHA256 Hash based encryption
def SHA256Encryption():
    textEncryption = input('Enter text to be encrypted.\n')
    #Encodes the string to SHA256
    SHA256Encrypt = hashlib.sha256(textEncryption.encode())
    SHA256Digest = SHA256Encrypt.hexdigest()
    print('[+] SHA256 Encoded String: ', SHA256Digest)

#Base64 Text Encryption
def base64Encryption():
    textEncryption = input('Enter text to be encrypted.\n')
    #Encodes string into bytes
    b = textEncryption.encode("UTF-8")
    #Base64 encode the bytes
    e = base64.b64encode(b)
    #Decode the Base64 bytes to string
    s1 = e.decode("UTF-8")
    #Print Base64 encoded string
    print('[+] Base64 Encoded String:', s1)


print('With this program you can encrypt a file or text into different encryptions.')
mainMenuChoice = input('Text or File Encryption? (1 for Text, 2 for File)\n')

def mainMenu():
    if mainMenuChoice == '1':
        textMenu()
    elif mainMenuChoice == '2':
        fileMenu()
    else:
        print('You must select what is in the menu.')
        mainMenu()

mainMenu()
