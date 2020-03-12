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


#Encrypting the file
def symmetric_encryption(option):
    #Create encryption key and store it in a file
    encryptionKey = Fernet.generate_key()
    file = open('key.key', 'wb')
    file.write(encryptionKey)
    file.close()
    print("[+] Stored encryption key in key.key\n")

    #Asks for file location and verifies if it exists
    if path.exists(option):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    
    #Asks for the encrypted file to be stored
    output_file = input("Enter output file to store encrypted data: ")

    #Reads input file and stored content into data
    with open(option, 'rb') as f:
        data = f.read()

    #Encrypts data using fernet key
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
    #Verifies if the file exists
    if path.exists(option):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)

    with open(option, 'rb') as f:
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
    #Verifies if inputted file exists
    if path.exists(option):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    #The size of each read from the file
    BLOCKSIZE = 65536
    #Create the hash object in MD5
    hasher = hashlib.md5()
    #Open the file to read it's bytes
    with open(option, 'rb') as afile:
        #Read from the file. Take in the BLOCKSIZE amount
        buf = afile.read(BLOCKSIZE)
        #While there is still data being read from the file
        while len(buf) > 0:
            #Update the hash
            hasher.update(buf)
            #Read the next block from the file
            buf = afile.read(BLOCKSIZE)
    print("\n[+] Hash has been generated")
    #Get the hexadecimal digest of the hash
    print("\nMD5 hash of ",option, ":\n" ,hasher.hexdigest(), sep="")

#SHA1 Hash of File
def SHA1_hash(option):
    #Verifies if inputted file exists
    if path.exists(option):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    #The size of each read from the file
    BLOCKSIZE = 65536
    #Create the hash object in SHA1
    hasher = hashlib.sha1()
    #Open the file to read it's bytes
    with open(option, 'rb') as afile:
        #Read from the file. Take in the BLOCKSIZE amount
        buf = afile.read(BLOCKSIZE)
        #While there is still data being read from the file
        while len(buf) > 0:
            #Update the hash
            hasher.update(buf)
            #Read the next block from the file
            buf = afile.read(BLOCKSIZE)
    print("\n[+] Hash has been generated")
    #Get the hexadecimal digest of the hash
    print("\nSHA1 hash of ",option, ":\n" ,hasher.hexdigest(), sep="")

#SHA256 Hash of File
def SHA256_hash(option):
    #Verifies if inputted file exists
    if path.exists(option):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    #The size of each read from the file
    BLOCKSIZE = 65536
    #Create the hash object in SHA256
    hasher = hashlib.sha256()
    #Open the file to read it's bytes
    with open(option, 'rb') as afile:
        #Read from the file. Take in the BLOCKSIZE amount
        buf = afile.read(BLOCKSIZE)
        #While there is still data being read from the file
        while len(buf) > 0:
            #Update the hash
            hasher.update(buf)
            #Read the next block from the file
            buf = afile.read(BLOCKSIZE)
    print('\n[+] Hash has been generated')
    #Get the hexadecimal digest of the hash
    print("\nSHA256 hash of ",option, ":\n" ,hasher.hexdigest(), sep="")

#SHA384 Hash of File
def SHA384_hash(option):
    #Verifies if inputted file exists
    if path.exists(option):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    #The size of each read from the file
    BLOCKSIZE = 65536
    #Create the hash object in SHA384
    hasher = hashlib.sha384()
    #Open the file to read it's bytes
    with open(option, 'rb') as afile:
        #Read from the file. Take in the BLOCKSIZE amount
        buf = afile.read(BLOCKSIZE)
        #While there is still data being read from the file
        while len(buf) > 0:
            #Update the hash
            hasher.update(buf)
            #Read the next block from the file
            buf = afile.read(BLOCKSIZE)
    print("\n[+] Hash has been generated")
    #Get the hexadecimal digest of the hash
    print("\nSHA384 hash of ",option, ":\n" ,hasher.hexdigest(), sep="")

#SHA512 Hash of File
def SHA512_hash(option):
    #Verifies if inputted file exists
    if path.exists(option):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    #The size of each read from the file
    BLOCKSIZE = 65536
    #Create the hash object in SHA512
    hasher = hashlib.sha512()
    #Open the file to read it's bytes
    with open(option, 'rb') as afile:
        #Read from the file. Take in the BLOCKSIZE amount
        buf = afile.read(BLOCKSIZE)
        #While there is still data being read from the file
        while len(buf) > 0:
            #Update the hash
            hasher.update(buf)
            #Read the next block from the file
            buf = afile.read(BLOCKSIZE)
    print("\n[+] Hash has been generated")
    #Get the hexadecimal digest of the hash
    print("\nSHA512 hash of ",option, ":\n" ,hasher.hexdigest(), sep="")

#SHA3_256 Hash of File
def SHA3_256_hash(option):
    #Verifies if inputted file exists
    if path.exists(option):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    #The size of each read from the file
    BLOCKSIZE = 65536
    #Create the hash object in SHA3-256
    hasher = hashlib.sha3_256()
    #Open the file to read it's bytes
    with open(option, 'rb') as afile:
        #Read from the file. Take in the BLOCKSIZE amount
        buf = afile.read(BLOCKSIZE)
        #While there is still data being read from the file
        while len(buf) > 0:
            #Update the hash
            hasher.update(buf)
            #Read the next block from the file
            buf = afile.read(BLOCKSIZE)
    print("\n[+] Hash has been generated")
    #Get the hexadecimal digest of the hash
    print("\nSHA3-256 hash of ",option, ":\n" ,hasher.hexdigest(), sep="")

#SHA3_512 Hash of File
def SHA3_512_hash(option):
    #Verifies if inputted file exists
    if path.exists(option):
        print("[+] File exists")
    else:
        print("[+] File does not exist")
        sys.exit(0)
    #The size of each read from the file
    BLOCKSIZE = 65536
    #Create the hash object in SHA3-512
    hasher = hashlib.sha3_512()
    #Open the file to read it's bytes
    with open(option, 'rb') as afile:
        #Read from the file. Take in the BLOCKSIZE amount
        buf = afile.read(BLOCKSIZE)
        #While there is still data being read from the file
        while len(buf) > 0:
            #Update the hash
            hasher.update(buf)
            #Read the next block from the file
            buf = afile.read(BLOCKSIZE)
    print("\n[+] Hash has been generated")
    #Get the hexadecimal digest of the hash
    print("\nSHA3-512 hash of ",option, ":\n" ,hasher.hexdigest(), sep="")


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("--sym", type=symmetric_encryption, action="store", help="File input for symmetric encryption")
    parser.add_argument("--asym", type=asymmetric_encryption, action="store", help="File input for asymmetric encryption.")
    parser.add_argument("--md5", type=MD5_hash, action="store", help="Generates MD5 hash of file.")
    parser.add_argument("--sha1", type=SHA1_hash, action="store", help="Generates SHA1 hash of file.")
    parser.add_argument("--sha256", type=SHA256_hash, action="store", help="Generates SHA256 hash of file.")
    parser.add_argument("--sha384", type=SHA384_hash, action="store", help="Generates SHA384 hash of file.")
    parser.add_argument("--sha512", type=SHA512_hash, action="store", help="Generates SHA512 hash of file.")
    parser.add_argument("--sha3_256", type=SHA3_256_hash, action="store", help="Generates SHA3-256 hash of file.")
    parser.add_argument("--sha3_512", type=SHA3_512_hash, action="store", help="Generates SHA3-512 hash of file.")

    parser.parse_args()

if __name__ == "__main__":
    menu = """
    ______                             _
    |  ____|                           | |
    | |__   _ __   ___ _ __ _   _ _ __ | |_ ___ _ __
    |  __| | '_ \ / __| '__| | | | '_ \| __/ _ \ '__|
    | |____| | | | (__| |  | |_| | |_) | ||  __/ |
    |______|_| |_|\___|_|   \__, | .__/ \__\___|_|
                            __/ | |
                            |___/|_|
    """
    print(menu)
    print('==================================================')
    print('               Welcome to Encrypter')
    print('==================================================')
    print('        Use -h to list possible arguments')
    
    main()