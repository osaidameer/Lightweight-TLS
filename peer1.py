import time
import socket
import rsa
import pickle
import random
import pyDH
import hmac
import hashlib
from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256, SHA3_256
from Crypto import Random

# variables to store enc_choice choices for section 1
enc_choice = ""
xchg_choice = ""
hash_choice = ""
peer_pub_keyey = ""
privkey = ""
peer_pub_key = ""
aes_password = ""
des_password = ""
connection = False
sig_choice = ""
sig_list = ['DSS', 'DSA', 'ELgamal', 'RSA']

print('Welcome to the Chat Room!')
time.sleep(1)

client1 = socket.socket()
client1.bind((socket.gethostname(), 8080))

enc_list = ['AES', 'RSA', 'DES3']
xchg_list = ['DH', 'RSA', 'ECC']
hash_list = ['SHA512', 'SHA3', 'SHA256', 'HMAC']


name = input('Enter name: ')
enc_list.insert(0, name)
data = pickle.dumps(enc_list)
client1.listen(1)
print('\nWaiting for connection...')

# STAGE 1

# PICKING ENCRYPTION ALGORITHM


client2, addr = client1.accept()
data2 = pickle.loads(client2.recv(1024))
client_name = data2[0]
print('\n' + str(client_name) + ' has connected.')
client2.send(data)

print("\n\nSTAGE 1: \nPicking Encryption Algorithm\n\n")

intersection = list(set(data2).intersection(enc_list))
print('Common encryption algorithms : ' + str(intersection))

choice = input("\nChoose Encryption Algo from Common List (Enter as shown): ")
check = -1

for i in range(len(intersection)):
    if intersection[i] == choice:
        check = i

while check == -1:
    print("ERROR! Invalid Encryption Method")
    choice = input("\nChoose Encryption Algo from Common List (Enter as shown): ")
    # check = enc_list.find(choice)
    for i in range(len(intersection)):
        if intersection[i] == choice:
            check = i

client2.send(intersection[check].encode())

choice_rcv = client2.recv(1024).decode()
print('\n' + str(choice_rcv) + ' picked, based on priority')

enc_choice = choice_rcv  # this variable contains the Encryption Algorithm that has been picked


# PICKING KEY EXCHANGE MECHANISM

print("\n\nKEY EXCHANGE MECHANISM WILL BE PICKED BASED UPON ENCRYPTION ALGORITHM CHOSEN!")

"""
print("\n\nPicking Key Exchange Mechanism\n\n")

data = pickle.dumps(xchg_list)
data2 = pickle.loads(client2.recv(1024))
client2.send(data)

intersection = list(set(data2).intersection(xchg_list))
print('Common key exchange algorithms : ' + str(intersection))

choice = input("\nChoose Key Exchange Method from Common List (Enter as shown): ")
check = -1

for i in range(len(intersection)):
    if xchg_list[i] == choice:
        check = i

while check == -1:
    print("ERROR! Invalid Key Exchange Method")
    choice = input("\nChoose Key Exchange Method from Common List (Enter as shown): ")
    # check = enc_list.find(choice)
    for i in range(len(intersection)):
        if xchg_list[i] == choice:
            check = i

client2.send(xchg_list[check].encode())

choice_rcv = client2.recv(1024).decode()
print('\n' + str(choice_rcv) + ' picked, based on priority')

xchg_choice = choice_rcv
"""

# PICKING HASHING METHOD

print("\n\nPicking Hashing Mechanism\n\n")

data = pickle.dumps(hash_list)
data2 = pickle.loads(client2.recv(1024))
client2.send(data)

intersection = list(set(data2).intersection(hash_list))
print('Common hashing algorithms : ' + str(intersection))

choice = input("\nChoose Hashing Method from Common List (Enter as shown): ")
check = -1

for i in range(len(intersection)):
    if intersection[i] == choice:
        check = i

while check == -1:
    print("ERROR! Invalid Hashing Method")
    choice = input("\nChoose Hashing Method from Common List (Enter as shown): ")
    # check = enc_list.find(choice)
    for i in range(len(intersection)):
        if intersection[i] == choice:
            check = i

client2.send(intersection[check].encode())

choice_rcv = client2.recv(1024).decode()
print('\n' + str(choice_rcv) + ' picked from ' + str(client_name) + ', based on priority')

hash_choice = choice_rcv

# PICKING DIGITAL SIGNATURE MECHANISM

print("\n\nPicking Digital Signature Mechanism\n\n")

data = pickle.dumps(sig_list)
data2 = pickle.loads(client2.recv(1024))
client2.send(data)

intersection = list(set(data2).intersection(sig_list))
print('Common Digital Signature algorithms : ' + str(intersection))

choice = input("\nChoose Digital Signature Method from Common List (Enter as shown): ")
check = -1

for i in range(len(intersection)):
    if intersection[i] == choice:
        check = i

while check == -1:
    print("ERROR! Invalid Digital Signature Method")
    choice = input("\nChoose Digital Signature Method from Common List (Enter as shown): ")
    # check = enc_list.find(choice)
    for i in range(len(intersection)):
        if intersection[i] == choice:
            check = i

client2.send(intersection[check].encode())

choice_rcv = client2.recv(1024).decode()
print('\n' + str(choice_rcv) + ' picked from ' + str(client_name) + ', based on priority')

sig_choice = choice_rcv

# ENDING STAGE 1


if enc_choice == 'AES' or enc_choice == 'DES' or enc_choice == 'DES3':
    xchg_choice = 'DH'
else:
    xchg_choice = 'RSA'

print("\nSTAGE 1: \nEncryption Method: " + str(enc_choice) + "\nKey Exchange: " + str(xchg_choice) + "\nHashing Method: " + str(hash_choice) + "\nDigital Signature: " + str(sig_choice))

# STAGE 2

if enc_choice == 'AES':
    # use DH by default
    print("\n\nSTAGE 2: \nUsing Diffie Helmann to generate and exchange an AES password\n")
    diffie = pyDH.DiffieHellman()
    diffie_pub_key = diffie.gen_public_key()
    print("\nYour Public Key: ", str(diffie_pub_key))
    client2.send(str(diffie_pub_key).encode())
    peer_pub_key = int(client2.recv(4096).decode())
    diffie_shared_secret = diffie.gen_shared_key(peer_pub_key)
    print("\nShared Key: ", diffie_shared_secret)
    hash_obj = hashlib.sha256(diffie_shared_secret.encode())
    aes_password = hash_obj.hexdigest()
    print("\nAES Generated Password: ", str(aes_password))
elif enc_choice == 'RSA':
    # use RSA by default
    print("\n\nSTAGE 2: \nUsing RSA to generate and exchange RSA public keys password\n")
    (peer_pub_keyey, privkey) = rsa.newkeys(512)
    client2.send(pickle.dumps(peer_pub_keyey))

    peer_pub_key = pickle.loads(client2.recv(2048))
    print("Public Key: ", peer_pub_keyey)
    print(client_name + '\'s Public Key: ' + str(peer_pub_key))

elif enc_choice == 'DES3':
    # use DH by default
    print("\nUsing Diffie Helmann to generate and exchange a DES3 password\n")
    diffie = pyDH.DiffieHellman()
    diffie_pub_key = diffie.gen_public_key()
    print("\nYour Public Key: ", str(diffie_pub_key))
    client2.send(str(diffie_pub_key).encode())
    peer_pub_key = int(client2.recv(4096).decode())
    diffie_shared_secret = diffie.gen_shared_key(peer_pub_key)
    print("\nShared Key: ", diffie_shared_secret)
    # using sha256 by default to hash passwords, ensures passwords of a particular size
    hash_obj = hashlib.sha256(diffie_shared_secret.encode())
    des_password = hash_obj.hexdigest()
    print("\nDES Generated Password: ", str(des_password))

    privkey = Random.new().read(DES3.block_size)
    client2.send(pickle.dumps(privkey))

# Communication
print('\n\nSTAGE 3:')
print('Enter BYE to leave the chat room\n')
while True:
    message = input('You:')
    if message == 'BYE' or message == 'bye':
        message = 'Leaving Chat Room, Goodbye!'
        if enc_choice == 'RSA':
            sendlist = []
            digest = ''
            if hash_choice == 'SHA256':
                hash_function = SHA256.new()
                hash_function.update(message.encode())
                digest = hash_function.hexdigest()
            # elif hash_choice == 'HMAC':
            #     hash_function = SHA256.new()
            #     hmc = hmac.new(str(peer_pub_key).encode('utf-8'), message.encode('utf-8'), hash_function)
            #     digest = hmc.hexdigest()
            #     sendlist.insert(0, digest)
            elif hash_choice == 'SHA3':
                hash_function = SHA3_256.new()
                hash_function.update(message.encode())
                digest = hash_function.hexdigest()
            sendlist.insert(0, digest)
            message = rsa.encrypt(message.encode('utf8'), peer_pub_key)

            sendlist.insert(1, message)
            client2.send(pickle.dumps(sendlist))
        elif enc_choice == 'AES':
            sendlist = []
            digest = ''
            if hash_choice == 'SHA256':
                hash_function = SHA256.new()
                hash_function.update(message.encode())
                digest = hash_function.hexdigest()
                sendlist.insert(0, digest)
            elif hash_choice == 'SHA3':
                hash_function = SHA3_256.new()
                hash_function.update(message.encode())
                digest = hash_function.hexdigest()
                sendlist.insert(0, digest)
            elif hash_choice == 'HMAC':
                hash_function = SHA256.new()
                hmc = hmac.new(aes_password[:16].encode(), message.encode(), hash_function)
                digest = hmc.hexdigest()
                sendlist.insert(0, digest)
            aes = AES.new(aes_password[:16].encode(), AES.MODE_CBC)
            cipher = aes.encrypt(pad(message.encode(), AES.block_size))
            iv = b64encode(aes.iv).decode('utf-8')
            cipher = b64encode(cipher).decode('utf-8')
            written = iv + cipher
            sendlist.insert(1, written)
            client2.send(pickle.dumps(sendlist))
        elif enc_choice == 'DES':
            sendlist = []
            digest = ''
            if hash_choice == 'SHA256':
                hash_function = SHA256.new()
                hash_function.update(message.encode())
                digest = hash_function.hexdigest()
                sendlist.insert(0, digest)
            elif hash_choice == 'SHA3':
                hash_function = SHA3_256.new()
                hash_function.update(message.encode())
                digest = hash_function.hexdigest()
                sendlist.insert(0, digest)
            elif hash_choice == 'HMAC':
                hash_function = SHA256.new()
                hmc = hmac.new(peer_pub_key.encode(), message.encode(), hash_function)
                digest = hmc.hexdigest()
                sendlist.insert(0, digest)
            enc = DES3.new(peer_pub_key, DES3.MODE_OFB, privkey)
            ctext = enc.encrypt(message.encode())
            sendlist.insert(1, ctext)
            client2.send(pickle.dumps(sendlist))
        else:
            client2.send(message.encode())
        print("\n")
        break
    if enc_choice == 'RSA':
        sendlist = []
        digest = ''
        if hash_choice == 'SHA256':
            hash_function = SHA256.new()
            hash_function.update(message.encode())
            digest = hash_function.hexdigest()
        #print('sending hash', digest)
        # elif hash_choice == 'HMAC':
        #     hash_function = SHA256.new()
        #     hmc = hmac.new(str(peer_pub_key).encode(), message.encode(), hash_function)
        #     digest = hmc.hexdigest()
        #     sendlist.insert(0, digest)
        elif hash_choice == 'SHA3':
            hash_function = SHA3_256.new()
            hash_function.update(message.encode())
            digest = hash_function.hexdigest()
        sendlist.insert(0, digest)
        message = rsa.encrypt(message.encode('utf8'), peer_pub_key)
        # sendlist.insert(0, digest)
        sendlist.insert(1, message)
        #print(sendlist)
        client2.send(pickle.dumps(sendlist))

        rstr = client2.recv(2048)
        message = pickle.loads(rstr)
        #print(message)
        msg = message[1]
        msg = rsa.decrypt(msg, privkey)
        print(client_name, ':', msg.decode('utf8'))

        if hash_choice == 'SHA256':
            dechash = SHA256.new()
            dechash.update(msg)
            digest = dechash.hexdigest()
        # elif hash_choice == 'HMAC':
        #     dechash = SHA256.new()
        #     hmc = hmac.new(str(peer_pub_key).encode(), msg, hash_function)
        #     digest = hmc.hexdigest()
        elif hash_choice == 'SHA3':
            dechash = SHA3_256.new()
            dechash.update(msg)
            digest = dechash.hexdigest()
        #print(digest)
        #print(message[0])
        if message[0] != digest:
            print('Hashes not matched!\nTampering detected!')
        # print('receiving hash', digest)
    elif enc_choice == 'AES':
        sendlist = []
        digest = ''
        if hash_choice == 'SHA256':
            hash_function = SHA256.new()
            hash_function.update(message.encode())
            digest = hash_function.hexdigest()
            sendlist.insert(0, digest)
        elif hash_choice == 'SHA3':
            hash_function = SHA3_256.new()
            hash_function.update(message.encode())
            digest = hash_function.hexdigest()
            sendlist.insert(0, digest)
        elif hash_choice == 'HMAC':
            hash_function = SHA256.new()
            hmc = hmac.new(aes_password[:16].encode(), message.encode(), hash_function)
            digest = hmc.hexdigest()
            sendlist.insert(0, digest)
        temp = aes_password[:16]
        aes = AES.new(temp.encode(), AES.MODE_CBC)
        cipher = aes.encrypt(pad(message.encode(), AES.block_size))
        iv = b64encode(aes.iv).decode('utf-8')
        cipher = b64encode(cipher).decode('utf-8')
        written = iv+cipher
        sendlist.insert(1, written)
        client2.send(pickle.dumps(sendlist))

        spickle = client2.recv(2048)
        msg = pickle.loads(spickle)
        message = msg[1]
        iv = message[:24]
        iv = b64decode(iv)
        cipher = message[24:]
        cipher = b64decode(cipher)
        temp = aes_password[:16]
        aes = AES.new(temp.encode(), AES.MODE_CBC, iv)
        pt = aes.decrypt(cipher)
        pt = unpad(pt, AES.block_size)
        if hash_choice == 'SHA256':
            hash_function = SHA256.new()
            hash_function.update(pt)
            digest = hash_function.hexdigest()
        elif hash_choice == 'SHA3':
            hash_function = SHA3_256.new()
            hash_function.update(pt)
            digest = hash_function.hexdigest()
        elif hash_choice == 'HMAC':
            hash_function = SHA256.new()
            hmc = hmac.new(aes_password[:16].encode(), pt, hash_function)
            digest = hmc.hexdigest()
        if msg[0] != digest:
            print('Hashes not matched!\nTampering detected!')
        print(client_name, ':', pt.decode())
    elif enc_choice == 'DES':
        sendlist = []
        digest = ''
        if hash_choice == 'SHA256':
            hash_function = SHA256.new()
            hash_function.update(message.encode())
            digest = hash_function.hexdigest()
            sendlist.insert(0, digest)
        elif hash_choice == 'SHA3':
            hash_function = SHA3_256.new()
            hash_function.update(message.encode())
            digest = hash_function.hexdigest()
            sendlist.insert(0, digest)
        elif hash_choice == 'HMAC':
            hash_function = SHA256.new()
            hmc = hmac.new(peer_pub_key.encode(), message.encode(), hash_function)
            digest = hmc.hexdigest()
            sendlist.insert(0, digest)
        enc = DES3.new(des_password.encode(), DES3.MODE_OFB, privkey)
        ctext = enc.encrypt(message.encode())
        sendlist.insert(1, ctext)
        client2.send(pickle.dumps(sendlist))

        str = client2.recv(2048)
        msg = pickle.loads(str)
        message = msg[1]
        dec = DES3.new(des_password.encode(), DES3.MODE_OFB, privkey)
        ptext = dec.decrypt(message)

        sendlist = []
        digest = ''
        if hash_choice == 'SHA256':
            hash_function = SHA256.new()
            hash_function.update(ptext)
            digest = hash_function.hexdigest()
        elif hash_choice == 'SHA3':
            hash_function = SHA3_256.new()
            hash_function.update(ptext)
            digest = hash_function.hexdigest()
        elif hash_choice == 'HMAC':
            hash_function = SHA256.new()
            hmc = hmac.new(peer_pub_key.encode(), ptext, hash_function)
            digest = hmc.hexdigest()
        print(client_name, ':', ptext.decode())
        if msg[0] != digest:
            print('Hashes not matched!\nTampering detected!')
    else:
        client2.send(message.encode())
        message = client2.recv(1024)
        message = message.decode()
        print(client_name, ':', message)

client2.close()