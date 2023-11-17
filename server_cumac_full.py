# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

### UDP server

import socket
import os
import hashlib

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
c = []


# Listen for incoming datagrams - full authentication
i = 0
while(i<frag):

    # seperate message-tag packet from client address
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    cipher = bytesAddressPair[0]
    address = bytesAddressPair[1]    
    
    # seperate message from message-tag, store message in list 'c', calculate hash of message
    msg = cipher[0:12]
    c.append(cipher[12:])
    hsh = hashlib.sha256(msg).hexdigest()

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
    
    # Sending a reply to client
    UDPServerSocket.sendto(bytesToSend, address)
    i = i + 1



# verify tags with the cipher of each message stored in list 'c'
# as tags are in str, they have to be converted using hex(). as the resulting output is also str, tag values were individually declared    

# tag1[0]
if (c[0] == str(0xd682ed4ca4d989c1)):  # sha 256
#if (c[0] == str(0x103ca96c06a1ce798f08f8ef)):  # sha 384
    print("message 1 verified")
else:
    print("message 1 not verified")
    
# tag2[0]^tag1[1]
if (c[1] == str((0xd682ed4ca4d989c1)^(0x34ec94f1551e1ec5))):  # sha 256
#if (c[1] == str((0x103ca96c06a1ce798f08f8ef)^(0xf0dfb0ccdb567d48b285b23d))):  # sha 384
    print("message 2 verified")
else:
    print("message 2 not verified")

# tag3[0]^tag2[1]^tag1[2]
if (c[2] == str((0xd682ed4ca4d989c1)^(0x34ec94f1551e1ec5)^(0x80dd6d5a6ecde9f3))):  # sha 256
#if (c[2] == str((0x103ca96c06a1ce798f08f8ef)^(0xf0dfb0ccdb567d48b285b23d)^(0x0cd773454667a3c2fa5f1b58))):  # sha 384
    print("message 3 verified")
else:
    print("message 3 not verified")

# tag4[0]^tag3[1]^tag2[2]^tag1[3]
if (c[3] == str((0xd682ed4ca4d989c1)^(0x34ec94f1551e1ec5)^(0x80dd6d5a6ecde9f3)^(0xd35e6e4a717fbde4))):  # sha 256
#if (c[3] == str((0x103ca96c06a1ce798f08f8ef)^(0xf0dfb0ccdb567d48b285b23d)^(0x0cd773454667a3c2fa5f1b58)^(0xd9cdf2329bd9979730bfaaff))):  # sha 384
    print("message 4 verified")
else:
    print("message 4 not verified")

