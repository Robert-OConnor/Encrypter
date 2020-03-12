#!/usr/bin/python3

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import argparse
import hashlib
from os import path
import sys

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
print('               Welcome to Encrypter')
print('==================================================')
print('        Use -h to list possible arguments')

#Encrypting the file
def symmetric_encryption(option):
    #Create encryption key and store it in a file
    encryptionKey = Fernet.generate_key()
    file = open('key.key', 'wb')
    file.write(encryptionKey)
    file.close()
    print("[+] Stored encryption key in key.key\n")

    #Asks for file location and verifies if it exists
    input_file = option
    if path.exists(input_file):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    
    #Asks for the encrypted file to be stored
    output_file = input("Enter output file to store encrypted data: ")

    #Reads input file and stored content into data
    with open(input_file, 'rb') as f:
        data = f.read()

    #Encrypts data
    fernet = Fernet(encryptionKey)    
    encrypted = fernet.encrypt(data)

    #Writes encrypted data to output_file
    with open(output_file, 'wb') as f:
        f.write(encrypted)
        print("[+] Finished Encrypting File")


def asymmetric_encryption(option):
    #Generates an RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()


    pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    #Stores the RSA private key into private_key.pem
    with open('private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    #Stores the RSA public key into the public_key.pem
    with open('public_key.pem', 'wb') as f:
        f.write(pem)

    #Asks for the input file to be encrypted
    input_file = option
    #Verifies if the file exists
    if path.exists(input_file):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)

    with open(input_file, 'rb') as f:
        data = f.read()

    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    output_file = input("Enter output file to store encrypted data: ")

    with open(output_file, 'wb') as f:
        f.write(encrypted)
        print("[+] Finished Encrypting File")


#MD5 Hash of File
def MD5_hash(option):
    input_file = option
    if path.exists(input_file):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    BLOCKSIZE = 65536 #The size of each read from the file
    hasher = hashlib.md5() #Create the hash object in MD5
    with open(input_file, 'rb') as afile: #Open the file to read it's bytes
        buf = afile.read(BLOCKSIZE) #Read from the file. Take in the BLOCKSIZE amount
        while len(buf) > 0: #While there is still data being read from the file
            hasher.update(buf) #Update the hash
            buf = afile.read(BLOCKSIZE) #Read the next block from the file
    print('\n[+] Hash has been generated')
    print('This is the MD5 hash of the ',input_file, 'file:\n' ,hasher.hexdigest()) #Get the hexadecimal digest of the hash

#SHA1 Hash based encryption
def SHA1_hash(option):
    input_file = option
    if path.exists(input_file):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    BLOCKSIZE = 65536 #The size of each read from the file
    hasher = hashlib.sha1() #Create the hash object in SHA1
    with open(input_file, 'rb') as afile: #Open the file to read it's bytes
        buf = afile.read(BLOCKSIZE) #Read from the file. Take in the BLOCKSIZE amount
        while len(buf) > 0: #While there is still data being read from the file
            hasher.update(buf) #Update the hash
            buf = afile.read(BLOCKSIZE) #Read the next block from the file
    print('\n[+] Hash has been generated')
    print('This is the SHA1 hash of the ',input_file, 'file:\n' ,hasher.hexdigest()) #Get the hexadecimal digest of the hash

#SHA256 Hash based encryption
def SHA256_hash(option):
    input_file = option
    if path.exists(input_file):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    BLOCKSIZE = 65536 #The size of each read from the file
    hasher = hashlib.sha256() #Create the hash object in SHA256
    with open(input_file, 'rb') as afile: #Open the file to read it's bytes
        buf = afile.read(BLOCKSIZE) #Read from the file. Take in the BLOCKSIZE amount
        while len(buf) > 0: #While there is still data being read from the file
            hasher.update(buf) #Update the hash
            buf = afile.read(BLOCKSIZE) #Read the next block from the file
    print('\n[+] Hash has been generated')
    print('This is the SHA256 hash of the ',input_file, 'file:\n' ,hasher.hexdigest()) #Get the hexadecimal digest of the hash

#SHA512 Hash based encryption
def SHA512_hash(option):
    input_file = option
    if path.exists(input_file):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    BLOCKSIZE = 65536 #The size of each read from the file
    hasher = hashlib.sha512() #Create the hash object in SHA512
    with open(input_file, 'rb') as afile: #Open the file to read it's bytes
        buf = afile.read(BLOCKSIZE) #Read from the file. Take in the BLOCKSIZE amount
        while len(buf) > 0: #While there is still data being read from the file
            hasher.update(buf) #Update the hash
            buf = afile.read(BLOCKSIZE) #Read the next block from the file
    print('\n[+] Hash has been generated')
    print('This is the SHA512 hash of the ',input_file, 'file:\n' ,hasher.hexdigest()) #Get the hexadecimal digest of the hash

parser = argparse.ArgumentParser()

parser.add_argument("--sym", type=symmetric_encryption, action="store", help="File input for symmetric encryption")
parser.add_argument("--asym", type=MD5_hash, action="store", help="File input for asymmetric encryption.")
parser.add_argument("--md5", type=MD5_hash, action="store", help="Generates MD5 hash of file.")
parser.add_argument("--sha1", type=SHA1_hash, action="store", help="Generates SHA1 hash of file.")
parser.add_argument("--sha256", type=SHA256_hash, action="store", help="Generates SHA256 hash of file.")
parser.add_argument("--sha512", type=SHA512_hash, action="store", help="Generates SHA512 hash of file.")

args = parser.parse_args()