# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

### UDP server

import socket
import os
import hashlib
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import math

# message used = 'abcdefghijkl'
frag = 4

# set IP, port and buffer size
localIP     = "127.0.0.1"
localPort   = 20001
bufferSize  = 1024

# set transmission rate to simulate NB-IoT performance
def calc_delay(signal):
   rate = 0.18 * ( float(signal) + 46 ) / 40    # bandwidth = 0.18M, rx power signals = 46 dBm and 23 dBm,divide by difference (gain) of 40dBm
   return(rate)

rate_cmd = 'iwconfig wlan0 rate %sM" % calc_delay(signal)'
os.system(rate_cmd)


# declare message to be sent to sender upon receiving a packet
msgFromServer       = "Hello UDP Client"
bytesToSend         = str.encode(msgFromServer)
 


## RSA program for signature encryption
private_key = RSA.generate(1024)
#Generating the public key (RsaKey object) from the private key
public_key = private_key.publickey()
print(type(private_key), type(public_key))#Converting the RsaKey objects to string 
private_pem = private_key.export_key().decode()
public_pem = public_key.export_key().decode()
print(type(private_pem), type(public_pem))#Writing down the private and public keys to 'pem' files
with open('private_pem.pem', 'w') as pr:
    pr.write(private_pem)
with open('public_pem.pem', 'w') as pu:
    pu.write(public_pem)
    
#Importing keys from files, converting it into the RsaKey object   
sk_key = RSA.import_key(open('private_pem.pem', 'r').read())
pk_key = RSA.import_key(open('public_pem.pem', 'r').read())

#print(type(pr_key), type(pu_key))#Instantiating PKCS1_OAEP object with the public key for encryption
cipher = PKCS1_OAEP.new(key=pk_key)
#Encrypting the message with the PKCS1_OAEP object
#cipher_text = cipher.encrypt(message+message1)
decrypt = PKCS1_OAEP.new(key=sk_key)
#Decrypting the message with the PKCS1_OAEP object
#decrypted_message = decrypt.decrypt(cipher_text)
##

message = 'Lorem Ipsum text'
encrypted_message = cipher.encrypt(message)

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip
UDPServerSocket.bind((localIP, localPort)) 

print("UDP listening")
 

cipher_array = []
tag1 = []
tag2 = []
tag3 = []
tag4 = []
h = []

# Listen for incoming datagrams - real-time authentication
i = 0
while(i<4):
#while(True):
    
    # seperate message-tag packet from client address
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    enc_message = bytesAddressPair[0]
    address = bytesAddressPair[1]
    
    # seperate message from message-tag, calculate hash of message
    msg = enc_message[0:16]
    hsh = hashlib.sha256(msg).hexdigest()
    
    #print(cipher)
    #print(cipher[16:45])
    #print(cipher[45:])
    
    
    # calculate length of each fragment and divide hash into 4 fragments. store in h
    n = len(hsh)/4
    
    j = 0
    while (j<4) :
        h.append(hsh[j*n:(j+1)*n])
        j = j + 1


    # store the hashes in tags
    # tag1 = [h1[0],h1[1],h1[2],h1[3]]
    tag1.append(h[0+i])
    
    # tag2 = [h2[0],h2[1],h2[2],h2[3]]
    try:
        tag2.append(h[4+i])
    except IndexError:
        pass
    
    # tag3 = [h3[0],h3[1],h3[2],h3[3]]
    try:
        tag3.append(h[8+i])
    except IndexError:
        pass

    # tag4 = [h4[0],h4[1],h4[2],h4[3]]
    try:
        tag4.append(h[12+i])
    except IndexError:
        pass


    # verify tags with the cipher of each message. for each 'i', cipher of different is compared
    # as tags are in str, they have to be converted using hex(). as the resulting output is also str, tag values were individually declared    

    # tag1[0]
    if (i==0):
        if (enc_message[16:44] == str(0xd682ed4ca4d989c1)):  # sha 256
        #if (enc_message[12:] == str(0x103ca96c06a1ce798f08f8ef)):   # sha 384
            print("message 1 verified")
        else:
            print("message 1 not verified")  # decrypt signature to retrieve message
            #decrypted_message1 = decrypt.decrypt(cipher[44:])
            decrypted_message1 = decrypt.decrypt(encrypted_message)
            print("message 1 retrieved")
    
    # tag2[0]^tag1[1]
    if (i==1):
        if (enc_message[16:44] == str((0xd682ed4ca4d989c1)^(0x34ec94f1551e1ec5))):  # sha 256
        #if (enc_message[12:] == str((0x103ca96c06a1ce798f08f8ef)^(0xf0dfb0ccdb567d48b285b23d))):  # sha 384
            print("message 2 verified")
        else:
            print("message 2 not verified")
            #decrypted_message2 = decrypt.decrypt(enc_message[44:])
            decrypted_message2 = decrypt.decrypt(encrypted_message)
            print("message 2 retrieved")
    

    # tag3[0]^tag2[1]^tag1[2]
    if (i==2):
        if (enc_message[16:44] == str((0xd682ed4ca4d989c1)^(0x34ec94f1551e1ec5)^(0x80dd6d5a6ecde9f3))):  # sha 256
        #if (enc_message[12:] == str((0x103ca96c06a1ce798f08f8ef)^(0xf0dfb0ccdb567d48b285b23d)^(0x0cd773454667a3c2fa5f1b58))):  # sha 384
            print("message 3 verified")
        else:
            print("message 3 not verified")
            #decrypted_message3 = decrypt.decrypt(enc_message[44:])
            decrypted_message3 = decrypt.decrypt(encrypted_message)
            print("message 3 retrieved")
    

    # tag4[0]^tag3[1]^tag2[2]^tag1[3]
    if (i==3):
        if (enc_message[16:44] == str((0xd682ed4ca4d989c1)^(0x34ec94f1551e1ec5)^(0x80dd6d5a6ecde9f3)^(0xd35e6e4a717fbde4))):  # sha 256
        #if (enc_message[12:] == str((0x103ca96c06a1ce798f08f8ef)^(0xf0dfb0ccdb567d48b285b23d)^(0x0cd773454667a3c2fa5f1b58)^(0xd9cdf2329bd9979730bfaaff))):  # sha 384
            print("message 4 verified")
        else:
            print("message 4 not verified")
            #decrypted_message4 = decrypt.decrypt(enc_message[44:])
            decrypted_message4 = decrypt.decrypt(encrypted_message)
            print("message 4 retrieved")
    
    
    
    # Sending a reply to client
    UDPServerSocket.sendto(bytesToSend, address)
    i = i + 1
    