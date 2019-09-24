#!/usr/bin/python3

#Version 1.0

#Created by: Robert O'Connor
#Class: NTS370
#This program will encrypt a file
#and can create hashes of files.

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

#File Menu function to show file encryption options
def fileMenu():
    fileChoice = input('''
    =========================================
    Now choose the method of file encryption.
    =========================================

    1. Symmetric Encryption
    2. Quit\n
    ''')

    if fileChoice == '1':
        symmetricEncryption()
    elif fileChoice == '2':
        print('Exiting program.')
        sys.exit(0)
    else:
        print('You must select what is in the menu.')
        fileMenu()

#Encrypting the file
def symmetricEncryption():
    encryptionKey = Fernet.generate_key()

    #Verifies the file exists
    fileLocation = input("Enter the path of your file: ")
    assert os.path.exists(fileLocation), "[+] There is no file in that location."
    fileMode = open(fileLocation, 'r+')
    print('[+] File Exists')
    fileMode.close()
    fileOutput = 'encryptedFile.encrypted'

    with open(fileLocation, 'rb') as fileMode:
        data = fileMode.read()
    #Encrypts the file
    fernet = Fernet(encryptionKey)
    encrypted = fernet.encrypt(data)

    with open(fileOutput, 'wb') as fileMode:
        fileMode.write(encrypted)

    print('\n[+] The key for the encrypted file is in single quotes: ', encryptionKey)
    print('\nIt is recommended you keep the key somewhere safe because that')
    print('is the only way to decrypt the file.\n')
    print('[+] File has been encrypted')

#Text Menu function to show text encryption choices
def hashGeneration():
    textChoice = input('''
    ==========================================
    Choose the method of file hash generation.
    ==========================================

    1. MD5 Hash
    2. SHA1 Hash
    3. SHA256 Hash
    4. SHA512 Hash
    5. Quit\n
    ''')

    if textChoice == '1':
        MD5Hash()
    elif textChoice == '2':
        SHA1Hash()
    elif textChoice == '3':
        SHA256Hash()
    elif textChoice == '4':
        SHA512Hash()
    elif textChoice == '5':
        print('Exiting program.')
        sys.exit(0)
    else:
        print('You must select what is in the menu.')
        hashGeneration()

#MD5 Hash based encryption
def MD5Hash():
    fileLocation = input("Enter the path of your file: ")
    assert os.path.exists(fileLocation), "[+] There is no file in that location."
    fileMode = open(fileLocation, 'r+')
    print('\n[+] File Exists')
    fileMode.close()
    BLOCKSIZE = 65536 #The size of each read from the file
    hasher = hashlib.md5() #Create the hash object in MD5
    with open(fileLocation, 'rb') as afile: #Open the file to read it's bytes
        buf = afile.read(BLOCKSIZE) #Read from the file. Take in the BLOCKSIZE amount
        while len(buf) > 0: #While there is still data being read from the file
            hasher.update(buf) #Update the hash
            buf = afile.read(BLOCKSIZE) #Read the next block from the file
    print('\n[+] Hash has been generated')
    print('This is the MD5 hash of the ',fileLocation, 'file:\n' ,hasher.hexdigest()) #Get the hexadecimal digest of the hash

#SHA1 Hash based encryption
def SHA1Hash():
    fileLocation = input("Enter the path of your file: ")
    assert os.path.exists(fileLocation), "[+] There is no file in that location."
    fileMode = open(fileLocation, 'r+')
    print('\n[+] File Exists')
    fileMode.close()
    BLOCKSIZE = 65536 #The size of each read from the file
    hasher = hashlib.sha1() #Create the hash object in SHA1
    with open(fileLocation, 'rb') as afile: #Open the file to read it's bytes
        buf = afile.read(BLOCKSIZE) #Read from the file. Take in the BLOCKSIZE amount
        while len(buf) > 0: #While there is still data being read from the file
            hasher.update(buf) #Update the hash
            buf = afile.read(BLOCKSIZE) #Read the next block from the file
    print('\n[+] Hash has been generated')
    print('This is the SHA1 hash of the ',fileLocation, 'file:\n' ,hasher.hexdigest()) #Get the hexadecimal digest of the hash

#SHA256 Hash based encryption
def SHA256Hash():
    fileLocation = input("Enter the path of your file: ")
    assert os.path.exists(fileLocation), "[+] There is no file in that location."
    fileMode = open(fileLocation, 'r+')
    print('\n[+] File Exists')
    fileMode.close()
    BLOCKSIZE = 65536 #The size of each read from the file
    hasher = hashlib.sha256() #Create the hash object in SHA256
    with open(fileLocation, 'rb') as afile: #Open the file to read it's bytes
        buf = afile.read(BLOCKSIZE) #Read from the file. Take in the BLOCKSIZE amount
        while len(buf) > 0: #While there is still data being read from the file
            hasher.update(buf) #Update the hash
            buf = afile.read(BLOCKSIZE) #Read the next block from the file
    print('\n[+] Hash has been generated')
    print('This is the SHA256 hash of the ',fileLocation, 'file:\n' ,hasher.hexdigest()) #Get the hexadecimal digest of the hash

#SHA512 Hash based encryption
def SHA512Hash():
    fileLocation = input("Enter the path of your file: ")
    assert os.path.exists(fileLocation), "[+] There is no file in that location."
    fileMode = open(fileLocation, 'r+')
    print('\n[+] File Exists')
    fileMode.close()
    BLOCKSIZE = 65536 #The size of each read from the file
    hasher = hashlib.sha512() #Create the hash object in SHA512
    with open(fileLocation, 'rb') as afile: #Open the file to read it's bytes
        buf = afile.read(BLOCKSIZE) #Read from the file. Take in the BLOCKSIZE amount
        while len(buf) > 0: #While there is still data being read from the file
            hasher.update(buf) #Update the hash
            buf = afile.read(BLOCKSIZE) #Read the next block from the file
    print('\n[+] Hash has been generated')
    print('This is the SHA512 hash of the ',fileLocation, 'file:\n' ,hasher.hexdigest()) #Get the hexadecimal digest of the hash



print('With this program you can encrypt a file and generate file hashes using different methods.')
mainMenuChoice = input('File Hash Generator or File Encryption? (1 for Hash, 2 for File Encryption)\n')

#Main menu function show text or file encryption choice
def mainMenu():
    if mainMenuChoice == '1':
        hashGeneration()
    elif mainMenuChoice == '2':
        fileMenu()
    else:
        print('You must select what is in the menu.')
        mainMenu()

#Calls main menu function to start program
mainMenu()
