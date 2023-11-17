# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

### UDP server

import socket
import os
import hashlib

frag = 4
seed = 10   # seed to generate new secret key everytime

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


message = 'Lorem Ipsum text'

#secretKey = os.urandom(32)  # 256-bit random encryption key
secretKey = '|l\xf3\x07p\x18"R\x94Da\x03\xd7/\x91\r\xee\x85\x8f\xd1\xcf\xf2\x8a\xf8\xa6s\xc5Q\x8e\xe3k\xf7'


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
    
    if(i == 0):
        secretKey = '|l\xf3\x07p\x18"R\x94Da\x03\xd7/\x91\r\xee\x85\x8f\xd1\xcf\xf2\x8a\xf8\xa6s\xc5Q\x8e\xe3k\xf7'
    elif(i == 1):
        seed = seed + 1
        secretKey = '|l\xf3\x07p\x18"R\x94Da\x03\xd7/\x91\r\xee\x85\x8f\xd1\xcf\xf2\x8a\xf8\xa6s\xc5Q\x8e\xe3k\xf1'
    elif(i == 2):
        seed = seed + 1
        secretKey = '|l\xf3\x07p\x18"R\x94Da\x03\xd7/\x91\r\xee\x85\x8f\xd1\xcf\xf2\x8a\xf8\xa6s\xc5Q\x8e\xe3k\xf2'
    else:
        seed = seed + 1
        secretKey = '|l\xf3\x07p\x18"R\x94Da\x03\xd7/\x91\r\xee\x85\x8f\xd1\xcf\xf2\x8a\xf8\xa6s\xc5Q\x8e\xe3k\xf3'
    
    
    # seperate message-tag packet from client address
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    enc_message = bytesAddressPair[0]
    address = bytesAddressPair[1]
    
    # seperate message from message-tag, calculate hash of message
    msg = enc_message[0:16]
    hsh = hashlib.sha256(msg+secretKey+str(i)).hexdigest()
        
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
        tag3.append(h[4+i])
    except IndexError:
        pass
    
    # tag3 = [h3[0],h3[1],h3[2],h3[3]]
    try:
        tag4.append(h[8+i])
    except IndexError:
        pass

    # tag4 = [h4[0],h4[1],h4[2],h4[3]]
    try:
        tag2.append(h[12+i])
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
    
    # tag2[0]^tag1[1]
    if (i==1):
        if (enc_message[16:44] == str((0xd682ed4ca4d989c1)^(0x34ec94f1551e1ec5))):  # sha 256
        #if (enc_message[12:] == str((0x103ca96c06a1ce798f08f8ef)^(0xf0dfb0ccdb567d48b285b23d))):  # sha 384
            print("message 2 verified")
        else:
            print("message 2 not verified")
    

    # tag3[0]^tag2[1]^tag1[2]
    if (i==2):
        if (enc_message[16:44] == str((0xd682ed4ca4d989c1)^(0x34ec94f1551e1ec5)^(0x80dd6d5a6ecde9f3))):  # sha 256
        #if (enc_message[12:] == str((0x103ca96c06a1ce798f08f8ef)^(0xf0dfb0ccdb567d48b285b23d)^(0x0cd773454667a3c2fa5f1b58))):  # sha 384
            print("message 3 verified")
        else:
            print("message 3 not verified")
    

    # tag4[0]^tag3[1]^tag2[2]^tag1[3]
    if (i==3):
        if (enc_message[16:44] == str((0xd682ed4ca4d989c1)^(0x34ec94f1551e1ec5)^(0x80dd6d5a6ecde9f3)^(0xd35e6e4a717fbde4))):  # sha 256
        #if (enc_message[12:] == str((0x103ca96c06a1ce798f08f8ef)^(0xf0dfb0ccdb567d48b285b23d)^(0x0cd773454667a3c2fa5f1b58)^(0xd9cdf2329bd9979730bfaaff))):  # sha 384
            print("message 4 verified")
        else:
            print("message 4 not verified")
    
    
    
    # Sending a reply to client
    UDPServerSocket.sendto(bytesToSend, address)
    i = i + 1
    