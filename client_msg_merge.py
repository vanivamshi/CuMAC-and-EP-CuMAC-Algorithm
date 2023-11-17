# -*- coding: utf-8 -*-
"""
Created on Sat Oct 16 12:36:05 2021

@author: vamshi
"""

### UDP client

import socket
import os
import hashlib
import random
import time

## Convert tuple to string
def convertTuple(tup):
    str = ''.join(tup)
    return str
##


## AES decryption
from Crypto.Cipher import AES
import binascii

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext


Key = '\x06L\xd2s\x9b\xc2[\x10\x1b\x98\xfax\x9c~\x1d[\xfa\xe4\x10\x90\x02\xcb\xe0\xcc\xb6\x1am\xf6j\xcd\x0b\xf2'  #os.urandom(32)  # 256-bit random encryption key
##

  
message1 = 'Lorem Ipsum text'
message2 = 'Lorem Ipsum text'
message3 = 'Lorem Ipsum text'
message4 = 'Lorem Ipsum text'


seed = 10   # seeed to generate secret keys
shuffle_seed = 11   # seed to shuffle tag list

#secretKey = os.urandom(32)  # 256-bit random encryption key
secretKey = '|l\xf3\x07p\x18"R\x94Da\x03\xd7/\x91\r\xee\x85\x8f\xd1\xcf\xf2\x8a\xf8\xa6s\xc5Q\x8e\xe3k\xf7'

seed = seed + 1
secretKey1 = '|l\xf3\x07p\x18"R\x94Da\x03\xd7/\x91\r\xee\x85\x8f\xd1\xcf\xf2\x8a\xf8\xa6s\xc5Q\x8e\xe3k\xf1'

seed = seed + 1
secretKey2 = '|l\xf3\x07p\x18"R\x94Da\x03\xd7/\x91\r\xee\x85\x8f\xd1\xcf\xf2\x8a\xf8\xa6s\xc5Q\x8e\xe3k\xf2'

seed = seed + 1
secretKey3 = '|l\xf3\x07p\x18"R\x94Da\x03\xd7/\x91\r\xee\x85\x8f\xd1\xcf\xf2\x8a\xf8\xa6s\xc5Q\x8e\xe3k\xf3'

# calculate hash
msg_hash = hashlib.sha256(message1+secretKey+'1').hexdigest()
msg_hash1 = hashlib.sha256(message2+secretKey1+'2').hexdigest()
msg_hash2 = hashlib.sha256(message3+secretKey2+'3').hexdigest()
msg_hash3 = hashlib.sha256(message4+secretKey3+'4').hexdigest()

#truncated_mac = (hashlib.sha256('Lorem Ipsum text').hexdigest())[:32] # truncate mac
# truncate to get last 128 characters
#l = len(str1)
#print(str1[l - 128:])

# timestamp encrypted with Key
#T = [str(int(time.time())), str(int(time.time())+1), str(int(time.time())+2), str(int(time.time())+3)]
T1 = encrypt_AES_GCM(str(int(time.time())), Key)
T2 = encrypt_AES_GCM(str(int(time.time())+1), Key)
T3 = encrypt_AES_GCM(str(int(time.time())+2), Key)
T4 = encrypt_AES_GCM(str(int(time.time())+3), Key)

T1 = convertTuple(T1)
T2 = convertTuple(T2)
T3 = convertTuple(T3)
T4 = convertTuple(T4)

T = [T1, T2, T3, T4]


# message to be sent has to be sent in 'bytesTo Send'
serverAddressPort   = ("127.0.0.1", 20001)
bufferSize          = 1024

#noise = 

def calc_delay(signal):
   rate = 0.18 * ( float(signal) + 46 ) / 70    # bandwidth = 0.18M, tx power signals = 46 dBm and 23 dBm,divide by difference (gain) of 70dBm
   return(rate)

rate_cmd = 'iwconfig wlan0 rate %sM" % calc_delay(signal)'
os.system(rate_cmd)


# fragment message
frag = input('Input number of fragments = ')
m = []
h = []
t = []
e = []
s = []

# split bytesToSend to 4 fragments and store in msg[]
length = len(message1)
n = length/frag

m.append(message1)
m.append(message2)
m.append(message3)
m.append(message4)

# merge m[0],m[1] and m[2],m[3]
m[1]= ",".join( item for item in m[0:2])
m[2]= ",".join( item for item in m[2:4])
del m[0]
del m[1]

#i = 0
#while (i<frag) :
#    m.append(message1[i*n:(i+1)*n])
#    i = i + 1


# fragment hash
# split bytesToSend to 4 fragments and store in msg[]
length = len(hashlib.sha256(message1).hexdigest())
n = length/frag

i = 0
while (i<frag) :
    h.append(msg_hash[i*n:(i+1)*n])
    i = i + 1


def prepend(list, mystr):
      
    # Using format()
    mystr += '{0}'
    list = [mystr.format(i) for i in list]
    return(list)

mystr = '0x'
h = prepend(h, mystr)
#print(h)
#an_integer = int(h, 16)
#h = hex(an_integer)


#for i in range(0, len(h)):
#    h[i] = hex(h[i])

h = [0x103ca96c06a1ce798f08f8ef, 0xf0dfb0ccdb567d48b285b23d, 0x0cd773454667a3c2fa5f1b58, 0xd9cdf2329bd9979730bfaaff]
#h = [0x103ca96c06a1, 0xce798f08f8ef, 0xf0dfb0ccdb56, 0x7d48b285b23d,
#     0x0cd773454667, 0xa3c2fa5f1b58, 0xd9cdf2329bd9, 0x979730bfaaff]


# calculate tags from hash fragments
t.append(h[0])
t.append(h[1]^h[0])
t.append(h[2]^h[1]^h[0])
t.append(h[3]^h[2]^h[1]^h[0])

#t.append(h[4]^h[3]^h[2]^h[1])
#t.append(h[5]^h[4]^h[3]^h[2])
#t.append(h[6]^h[5]^h[4]^h[3])
#t.append(h[7]^h[6]^h[5]^h[4])


t = ['5025095778980253837715634415',
 '69599189387669389377364904658',
 '73101831266818452109753733514',
 '16704449815391399881558850421']

#t = ['17852726511265', '244388578262606', '51241487443224', '92162015205157',
#     '87110493460451', '37944078578772', '12716486784219', '247730686880793']


# merge m[0],m[1] and m[2],m[3]
t[1]= ",".join( item for item in t[0:2])
t[2]= ",".join( item for item in t[2:4])
del t[0]
del t[1]


# append message, tag and signature
e = [x + y + z for x, y, z in zip(m, t, T)]


## shrink message+tag+timestamp (to consume less energy)
def xor_crypt_string(data, key = Key, encode = False, decode = False):
   from itertools import izip, cycle
   import base64
   
   if decode:
      data = base64.decodestring(data)
   xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
   
   if encode:
      return base64.encodestring(xored).strip()
   return xored

secret_data0 = e[0]
secret_data1 = e[1]

z1 = xor_crypt_string(secret_data0, encode = True)
z2 = xor_crypt_string(secret_data1, encode = True)

# Create a UDP socket at client side
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# send hash
UDPClientSocket.sendto(msg_hash, serverAddressPort)

#MESSAGE = pickle.dumps(e)
#TAG = pickle.dumps(t)

# send packets
UDPClientSocket.sendto(z1, serverAddressPort)
UDPClientSocket.sendto(z2, serverAddressPort)
#UDPClientSocket.sendto(e[2], serverAddressPort)
#UDPClientSocket.sendto(e[3], serverAddressPort)

msgFromServer = UDPClientSocket.recvfrom(bufferSize)

msg = "Message from Server {}".format(msgFromServer[0])

decryptedMsg = decrypt_AES_GCM(eval(msgFromServer[0]), Key)

print(decryptedMsg)
