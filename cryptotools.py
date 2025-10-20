#!/home/chitrakv/Documents/env/bin/python

from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA,DSA
from Crypto.Hash import SHA256, SHA512, SHA3_256
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from time import time
import os


def generateAESKey(size):
    return get_random_bytes(size)

def generateRSAKey(size):
    return RSA.generate(size)

def generateDSAKey(size):
    return DSA.generate(size)

def readFiles():
    with open('smallFile.txt','r') as file:
        smallFile = file.read().encode()

    with open('largeFile.txt','r') as file:
        largeFile = file.read().encode()

    with open('largeFile_1MB.txt','r') as file:
        largeFile_1MB = file.read().encode()
    return smallFile, largeFile, largeFile_1MB

#AES Encryption function based on CBC mode
def aesEncryption(key, plainText):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encryptedData = cipher.encrypt(pad(plainText,AES.block_size))
    return encryptedData, iv

#AES Decryption function based on CBC mode
def aesDecryption(key, encryptedData,iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encryptedData),AES.block_size)
    return decrypted.decode()

#CTR mode AES Encryption function
def aesCTRmode_encrypt(key, plaintext):
    iv = get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    cipherText = cipher.encrypt(plaintext)
    return cipherText,iv

#CTR mode AES Decryption function
def aesCTRmode_decrypt(key, cipherText,iv):
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    decrypted = cipher.decrypt(cipherText)
    return decrypted.decode()

def RSAencryption(data,publicKey):
    cipher = PKCS1_OAEP.new(publicKey)
    encryptedData = cipher.encrypt(data)
    return encryptedData

def RSAdecryption(encryptedData,privateKey):
    cipher = PKCS1_OAEP.new(privateKey)
    decryptedData = cipher.decrypt(encryptedData)
    return decryptedData

def computeHashing(data,hashType):
    hashedData = hashType.new(data).hexdigest()
    return hashedData

def generateSignature(key, data):
    hashedData = SHA256.new(data)
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(hashedData)
    return signature

def verifyDSA(key,data,signature):
    hashedData = SHA256.new(data)
    verifier = DSS.new(key.publickey(), 'fips-186-3')
    try:
        verifier.verify(hashedData, signature)
        print("Data is verified")
    except ValueError:
        print("Unable to verify the data")

smallFile, largeFile, largeFile_1MB = readFiles()
fileData = {'smallFile':smallFile,'largeFile':largeFile}
fileStorage = {'smallFile':os.path.getsize("smallFile.txt"),'largeFile':os.path.getsize("largeFile.txt"),'largeFile_1MB':os.path.getsize("largeFile_1MB.txt")}
totalTime_encrypt_={'128':0,'256':0}


bitSizeList = [128,256]
for bitLength in bitSizeList:
    startTime = time()
    totalTime_encrypt_CBC = 0
    totalTime_decrypt_CBC = 0
    totalTime_encrypt_CTR = 0
    totalTime_decrypt_CTR = 0

    totalSpeed_encrypt_CBC = 0
    totalSpeed_decrypt_CBC = 0
    totalSpeed_encrypt_CTR = 0
    totalSpeed_decrypt_CTR = 0
    #AES key generation
    key = generateAESKey(bitLength//8)
    print(f'\nTime taken to generate {bitLength}-bit AES key {(time()-startTime)*10**9} ns')
    for fileKey,file in fileData.items():
        print(f"\n------------- Stats for {fileKey} AES {bitLength}-bit encryption----------\n")
        startTime = time()
        encryptedData, iv = aesEncryption(key, file)
        duration = (time()-startTime)*10**9
        totalTime_encrypt_CBC+=duration
        print(f'Time Taken to encrypt {fileKey} using {bitLength}-bit AES CBC mode {duration} ns')
        totalSpeed_encrypt_CBC += fileStorage[fileKey]/duration
        print(f'Speed per byte to encrypt for {fileKey} using {bitLength}-bit AES CBC mode {fileStorage[fileKey]/duration} bytes/ns')
        
	

        startTime = time()
        decryptedData = aesDecryption(key, encryptedData, iv)
        duration = (time()-startTime)*10**9
        totalTime_decrypt_CBC+=duration
        print(f'Time Taken to decrypt {fileKey} using {bitLength}-bit AES CBC mode {duration} ns')
        totalSpeed_decrypt_CBC += fileStorage[fileKey]/duration
        print(f'Speed per byte to decrypt for {fileKey} using {bitLength}-bit AES CBC mode {fileStorage[fileKey]/duration} bytes/ns')


        #AES encryption and decryption in CTR mode
        startTime = time()
        encryptedData, iv = aesCTRmode_encrypt(key, file)
        duration = (time()-startTime)*10**9
        totalTime_encrypt_CTR+=duration
        print(f'Time Taken to encrypt {fileKey} using {bitLength}-bit AES CTR mode {duration} ns')
        totalSpeed_encrypt_CTR += fileStorage[fileKey]/duration
        print(f'Speed per byte to encrypt for {fileKey} using {bitLength}-bit AES CTR mode {fileStorage[fileKey]/duration} bytes/ns')

        startTime = time()
        decryptedData = aesCTRmode_decrypt(key, encryptedData, iv)
        duration = (time()-startTime)*10**9
        totalTime_decrypt_CTR+=duration
        print(f'Time Taken to decrypt {fileKey} using {bitLength}-bit AES CTR mode {duration} ns ')
        totalSpeed_decrypt_CTR += fileStorage[fileKey]/duration
        print(f'Speed per byte to decrypt for {fileKey} using {bitLength}-bit AES CTR mode {fileStorage[fileKey]/duration} bytes/ns \n')
    print(f'Total time taken to encrypt using AES-{bitLength} bit CBC mode {totalTime_encrypt_CBC} ns')
    print(f'Total time taken to decrypt using AES-{bitLength} bit CBC mode {totalTime_decrypt_CBC} ns')
    print(f'Total time taken to encrypt using AES-{bitLength} bit CTR mode {totalTime_encrypt_CTR} ns')
    print(f'Total time taken to decrypt using AES-{bitLength} bit CTR mode {totalTime_decrypt_CTR} ns')

    print(f'Total speed per byte to encrypt using AES-{bitLength} bit CBC mode {totalSpeed_encrypt_CBC} bytes/ns')
    print(f'Total speed per byte to decrypt using AES-{bitLength} bit CBC mode {totalSpeed_decrypt_CBC} bytes/ns')
    print(f'Total speed per byte to encrypt using AES-{bitLength} bit CTR mode {totalSpeed_encrypt_CTR} bytes/ns')
    print(f'Total speed per byte to decrypt using AES-{bitLength} bit CTR mode {totalSpeed_decrypt_CTR} bytes/ns')
	

print('\n################# RSA Encryption #################')

fileData = {'smallFile':smallFile,'largeFile_1MB':largeFile_1MB}
RSAkey_length = [2048,3072]

for rsaKey in RSAkey_length:
    startTime = time()
    #AES key generation
    key = generateRSAKey(rsaKey)
    print(f'\nTime taken to generate {rsaKey}-bit RSA key {(time()-startTime)*10**9} ns')
    
    totalTime_encrypt_RSA = 0
    totalTime_decrypt_RSA = 0
    totalSpeed_encrypt_RSA = 0
    totalSpeed_decrypt_RSA = 0
    for fileKey,file in fileData.items():
        print(f"\n------------- Stats for {fileKey} RSA {rsaKey}-bit encryption----------\n")
        msgLen = rsaKey//8 - 42
        out = []
        startTime = time()
        for i in range(0,len(file),msgLen):
            ciphertext = RSAencryption(file[i:i+msgLen], key.publickey())
            out.append(ciphertext)
        duration = round((time()-startTime)*10**6,2)
        totalTime_encrypt_RSA+=duration
        
        print(f'Time Taken to encrypt {fileKey} using RSA {rsaKey}-bit {duration} micro seconds')
        print(f'Speed per byte to encrypt for {fileKey} using RSA {rsaKey}-bit {fileStorage[fileKey]/duration} bytes/micro seconds')


        startTime=time()
        decrypted_text=''
        for i in out:
            decrypted_text+= RSAdecryption(i,key).decode()
        duration = round((time()-startTime)*10**6,2)
        totalTime_decrypt_RSA+=duration
        print(f'Time Taken to decrypt {fileKey} using RSA {rsaKey}-bit {duration} micro seconds')
        print(f'Speed per byte to decrypt for {fileKey} using RSA {rsaKey}-bit {fileStorage[fileKey]/duration} bytes/micro seconds\n')

    print(f'Total time taken to encrypt using RSA-{rsaKey} bit  {totalTime_encrypt_RSA} micro seconds')
    print(f'Total time taken to decrypt using RSA-{rsaKey} bit  {totalTime_decrypt_RSA} micro seconds')


hashTypes = {"SHA256":SHA256,"SHA512":SHA512,"SHA3_256":SHA3_256}
fileData = {'smallFile':smallFile,'largeFile':largeFile,'largeFile_1MB':largeFile_1MB}

print('\n############## Hashing ##############\n')

for hashKey,hashType in hashTypes.items():
    totalTime_hash = 0
    totalSpeed_hash=0
    for fileKey,file in fileData.items():
        startTime = time()
        out = computeHashing(file,hashType)
        duration = round((time()-startTime)*10**6,2)
        totalTime_hash+=duration
        print(f"Time taken to hash {fileKey} by {hashKey} technique {duration} micro seconds")
        totalSpeed_hash+=fileStorage[fileKey]/duration
        print(f'Speed per byte to hash for {fileKey} using {hashKey} technique {fileStorage[fileKey]/duration} bytes/micro seconds \n')

    print(f'Total time taken to hash using {hashKey} bit  {totalTime_hash} micro seconds \n')
    print(f'Total speed per byte taken to hash using {hashKey} bit  {totalSpeed_hash} bytes/micro seconds \n')


print('\n############## DSA ##############\n')
DSAkey_length = [2048,3072]
for DSAKey in DSAkey_length:
    startTime = time()
    totalTime_Sign = 0
    totalTime_verify = 0
    totalSpeed_Sign = 0
    totalSpeed_verify = 0
    #AES key generation
    key = generateDSAKey(DSAKey)
    print(f'\nTime taken to generate {DSAKey}-bit DSA key {(time()-startTime)*10**9} ns')
    for fileKey,file in fileData.items():
        startTime = time()
        signature = generateSignature(key, file)
        duration = round((time()-startTime)*10**9,2)
        totalTime_Sign+=duration
        print(f"Time taken to generate signature for {fileKey} by DSA-{DSAKey} bit {duration} ns")
        totalSpeed_Sign += fileStorage[fileKey]/duration
        print(f'Speed per byte to sign for {fileKey} using DSA-{DSAKey} bit  {fileStorage[fileKey]/duration} bytes/ns')

        startTime = time()
        verifyDSA(key,file,signature)
        duration = round((time()-startTime)*10**9,2)
        totalTime_verify+=duration
        print(f"Time taken to verify signature for {fileKey} by DSA-{DSAKey} bit {duration} ns")
        totalSpeed_verify += fileStorage[fileKey]/duration
        print(f'Speed per byte to verify signature for {fileKey} using DSA-{DSAKey} bit  {fileStorage[fileKey]/duration} bytes/ns \n')

    print(f'Total time taken to sign using DSA-{DSAKey} bit  {totalTime_Sign} ns')
    print(f'Total time taken to verify signature using DSA-{DSAKey} bit  {totalTime_verify} ns \n')

    print(f'Total speed per byte to sign using DSA-{DSAKey} bit  {totalSpeed_Sign} bytes/ns')
    print(f'Total speed per byte to verify signature using DSA-{DSAKey} bit  {totalSpeed_verify} bytes/ns \n')
        

print('\n############################\n')

