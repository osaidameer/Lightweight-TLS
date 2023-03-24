import time
import socket
import rsa
import pickle
import random
import pyDH
import hashlib
import hmac
from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256, SHA3_256


# variables to store enc_choice choices for section 1
enc_choice = ""
xchg_choice = ""
hash_choice = ""
aes_password = ""
des_password = ""
peer_pub_keyey = ""
privkey = ""
peer_pub_key = ""
sig_choice = ""
sig_list = ['DSS', 'DSA', 'ELgamal', 'RSA']

print('Welcome to the Chat Room!')
time.sleep(1)

client1 = socket.socket()

enc_list = ['AES', 'RSA', 'DES3']
xchg_list = ['DH', 'RSA']
hash_list = ['SHA3', 'SHA256', 'HMAC']

name = input('Enter Name: ')

enc_list.insert(0, name)
data = pickle.dumps(enc_list)

client1.connect((socket.gethostname(), 8080))


# PICKING ENCRYPTION ALGORITHMS


client1.send(data)
data2 = pickle.loads(client1.recv(1024))
client2_name = data2[0]

print('\n' + str(client2_name) + ' has connected')

print("\n\nPicking Encryption Algorithm\n\n")

print('The algorithms received from ' + str(client2_name) + ' are : ', end='')
print(str(data2[1:]))

intersection = list(set(data2).intersection(enc_list))
print('Common algorithms : ' + str(intersection))

print('Waiting on Peer to pick...')
choice_rcv = client1.recv(1024).decode()
print(client2_name + ' picked ' + str(choice_rcv))
choice = input("\nChoose Encryption Algo from Common List (Enter as shown): ")
check = -1

for i in range(len(intersection)):
    if intersection[i] == choice:
        check = i

# checking if input is found in intersection
while check == -1:
    print("ERROR! Invalid Encryption Method")
    choice = input("Choose Encryption Algo from Common List (Enter as shown): ")
    for i in range(len(intersection)):
        if intersection[i] == choice:
            check = i

# compares priority between received choice and picked choice, picks the algo with higher priority
if intersection[check] == choice_rcv:
    print(str(choice_rcv) + ' picked')
    client1.send(choice_rcv.encode())
    enc_choice = choice_rcv
else:
    for i in range(len(enc_list)):
        if enc_list[i] == choice_rcv:
            cmp1 = i
    for i in range(len(enc_list)):
        if enc_list[i] == choice:
            check = i
    if cmp1 <= check:
        print('\n' + str(choice_rcv) + ' picked, based on priority')
        enc_choice = choice_rcv
        client1.send(choice_rcv.encode())
    else:
        print('\n' + str(choice) + ' picked, based on priority')
        client1.send(choice.encode())
        enc_choice = choice


# PICKING KEY EXCHANGE MECHANISM

print("\n\nKEY EXCHANGE MECHANISM WILL BE PICKED BASED UPON ENCRYPTION ALGORITHM CHOSEN!")

"""
print("\n\nPicking Key Exchange Mechanism\n\n")

data = pickle.dumps(xchg_list)
client1.send(data)
data2 = pickle.loads(client1.recv(1024))

print('The algorithms received from ' + str(client2_name) + ' are : ', end='')
print(str(data2))

intersection = list(set(data2).intersection(xchg_list))
print('Common algorithms : ' + str(intersection))

print('Waiting on Peer to pick...')
choice_rcv = client1.recv(1024).decode()
print(client2_name + ' picked ' + str(choice_rcv))
choice = input("\nChoose Key Exchange from Common List (Enter as shown): ")
check = -1

for i in range(len(intersection)):
    if enc_list[i] == choice:
        check = i

while check == -1:
    print("ERROR! Invalid Key Exchange Method")
    choice = input("\nChoose Key Exchange Method from Common List (Enter as shown): ")
    for i in range(len(intersection)):
        if xchg_list[i] == choice:
            check = i

if xchg_list[check] == choice_rcv:
    print(str(choice_rcv) + ' picked')
    client1.send(choice_rcv.encode())
    xchg_choice = choice_rcv
else:
    for i in range(len(xchg_list)):
        if enc_list[i] == choice_rcv:
            cmp1 = i
            break
    for i in range(len(xchg_list)):
        if enc_list[i] == choice:
            check = i
            break
    if cmp1 <= check:
        print('\n' + str(choice_rcv) + ' picked, based on priority')
        xchg_choice = choice_rcv
        client1.send(choice_rcv.encode())
    else:
        print('\n' + str(choice) + ' picked, based on priority')
        client1.send(choice.encode())
        xchg_choice = choice
"""

# PICKING HASHING METHOD

print("\n\nPicking Hashing Mechanism\n\n")

data = pickle.dumps(hash_list)
client1.send(data)
data2 = pickle.loads(client1.recv(1024))

print('The hashing methods received from ' + str(client2_name) + ' are : ', end='')
print(str(data2))

intersection = list(set(data2).intersection(hash_list))
print('Common hashing methods: ' + str(intersection))

print('Waiting on Peer to pick...')
choice_rcv = client1.recv(1024).decode()
print(client2_name + ' picked ' + str(choice_rcv))
choice = input("\nChoose Hashing Method from Common List (Enter as shown): ")
check = -1

# follows the same format as encryption method to pick hashing algorithm
for i in range(len(intersection)):
    if intersection[i] == choice:
        check = i
        break

while check == -1:
    print("ERROR! Invalid Hashing Method")
    choice = input("\nChoose Hashing from Common List (Enter as shown): ")
    for i in range(len(intersection)):
        if intersection[i] == choice:
            check = i
            break

if intersection[check] == choice_rcv:
    print('\n' + str(choice_rcv) + ' picked')
    client1.send(choice_rcv.encode())
    hash_choice = choice_rcv
else:
    for i in range(len(hash_list)):
        if hash_list[i] == choice_rcv:
            cmp1 = i
            break

    for i in range(len(hash_list)):
        if hash_list[i] == choice:
            check = i
            break

    if cmp1 <= check:
        print('\n' + str(choice_rcv) + ' picked, based on priority')
        hash_choice = choice_rcv
        client1.send(choice_rcv.encode())
    else:
        print('\n' + str(choice) + ' picked, based on priority')
        client1.send(choice.encode())
        hash_choice = choice

if enc_choice == 'AES' or enc_choice == 'DES' or enc_choice == 'DES3':
    xchg_choice = 'DH'
else:
    xchg_choice = 'RSA'

# PICKING DIGITAL SIGNATURE METHOD

print("\n\nPicking Digital Signature Mechanism\n\n")

data = pickle.dumps(sig_list)
client1.send(data)
data2 = pickle.loads(client1.recv(1024))

print('The Digital Signature Methods received from ' + str(client2_name) + ' are : ', end='')
print(str(data2))

intersection = list(set(data2).intersection(sig_list))
print('Common Digital Signature Methods: ' + str(intersection))

print('Waiting on Peer to pick...')
choice_rcv = client1.recv(1024).decode()
print(client2_name + ' picked ' + str(choice_rcv))
choice = input("\nChoose Digital Signature Methods from Common List (Enter as shown): ")
check = -1

# follows the same format as encryption method to pick hashing algorithm
for i in range(len(intersection)):
    if intersection[i] == choice:
        check = i
        break

while check == -1:
    print("ERROR! Invalid Hashing Method")
    choice = input("\nChoose Digital Signature Method from Common List (Enter as shown): ")
    for i in range(len(intersection)):
        if intersection[i] == choice:
            check = i
            break

if intersection[check] == choice_rcv:
    print('\n' + str(choice_rcv) + ' picked')
    client1.send(choice_rcv.encode())
    sig_choice = choice_rcv
else:
    for i in range(len(sig_list)):
        if sig_list[i] == choice_rcv:
            cmp1 = i
            break

    for i in range(len(sig_list)):
        if sig_list[i] == choice:
            check = i
            break

    if cmp1 <= check:
        print('\n' + str(choice_rcv) + ' picked, based on priority')
        sig_choice = choice_rcv
        client1.send(choice_rcv.encode())
    else:
        print('\n' + str(choice) + ' picked, based on priority')
        client1.send(choice.encode())
        sig_choice = choice

print("\nSTAGE 1: \nEncryption Method: " + str(enc_choice) + "\nKey Exchange: " + str(xchg_choice) + "\nHashing Method: " + str(hash_choice) + "\nDigital Signature: " + str(sig_choice))

# STAGE 2

if enc_choice == 'AES':
    # use DH by default
    print("\nUsing Diffie Helmann to generate and exchange an AES password\n")
    diffie = pyDH.DiffieHellman()
    diffie_pub_key = diffie.gen_public_key()
    print("\nYour Public Key: ", str(diffie_pub_key))
    peer_pub_key = int(client1.recv(4096).decode())
    client1.send(str(diffie_pub_key).encode())
    diffie_shared_secret = diffie.gen_shared_key(peer_pub_key)
    print("\nShared Key: ", diffie_shared_secret)
    hash_obj = hashlib.sha256(diffie_shared_secret.encode())
    aes_password = hash_obj.hexdigest()
    print("\nAES Generated Password: ", str(aes_password))

elif enc_choice == 'RSA':
    # use RSA by default
    # use RSA by default
    print("\n\nSTAGE 2: \nUsing RSA to generate and exchange RSA public keys password\n")
    (peer_pub_keyey, privkey) = rsa.newkeys(512)
    peer_pub_key = pickle.loads(client1.recv(2048))

    client1.send(pickle.dumps(peer_pub_keyey))
    print("Public Key: ", peer_pub_keyey)
    print(client2_name + '\'s Public Key: ' + str(peer_pub_key))

elif enc_choice == 'DES3':
    print("\nUsing Diffie Helmann to generate and exchange a DES password\n")
    diffie = pyDH.DiffieHellman()
    diffie_pub_key = diffie.gen_public_key()
    print("\nYour Public Key: ", str(diffie_pub_key))
    peer_pub_key = int(client1.recv(4096).decode())
    client1.send(str(diffie_pub_key).encode())
    diffie_shared_secret = diffie.gen_shared_key(peer_pub_key)
    print("\nShared Key: ", diffie_shared_secret)
    hash_obj = hashlib.sha256(diffie_shared_secret.encode())
    des_password = hash_obj.hexdigest()
    print("\nDES Generated Password: ", str(des_password))

    str = client1.recv(2048)
    privkey = pickle.loads(str)

# Communication
print('\n\nSTAGE 3:')
print('Enter BYE to leave the chat room\n')
while True:
    if enc_choice == 'RSA':
        digest = ''
        sendlist = []
        rstr = client1.recv(2048)
        message = pickle.loads(rstr)
        #print(message)
        msg = message[1]
        msg = rsa.decrypt(msg, privkey)
        print(client2_name, ':', msg.decode('utf-8'))

        if hash_choice == 'SHA256':
            hash_function = SHA256.new()
            hash_function.update(msg)
            digest = hash_function.hexdigest()
        # elif hash_choice == 'HMAC':
        #     hash_function = SHA256.new()
        #     hmc = hmac.new(str(peer_pub_key).encode(), msg, hash_function)
        #     digest = hmc.hexdigest()
        elif hash_choice == 'SHA3':
            dechash = SHA3_256.new()
            dechash.update(msg)
            digest = dechash.hexdigest()
        #print(digest)
        #print(message[0])
        # print('receiving hash', digest)

        if message[0] != digest:
            print('Hashes not matched!\nTampering detected!')

        message = input('You:')
        if message == "BYE" or message == "bye":
            message = "Leaving Chat Room, Goodbye!"

            if hash_choice == 'SHA256':
                hash_function = SHA256.new()
                hash_function.update(message.encode())
                digest = hash_function.hexdigest()
            # elif hash_choice == 'HMAC':
            #     hash_function = SHA256.new()
            #     hmc = hmac.new(str(peer_pub_key).encode(), message.encode(), hash_function)
            #     digest = hmc.hexdigest()
            elif hash_choice == 'SHA3':
                hash_function = SHA3_256.new()
                hash_function.update(message.encode())
                digest = hash_function.hexdigest()
            sendlist.insert(0, digest)

            message = rsa.encrypt(message.encode('utf8'), peer_pub_key)
            sendlist.insert(1, message)

            client1.send(pickle.dumps(sendlist))
            print('')
            break

        if hash_choice == 'SHA256':
            hashenc = SHA256.new()
            hashenc.update(message.encode())
            digest = hashenc.hexdigest()
        # elif hash_choice == 'HMAC':
        #     hash_function = SHA256.new()
        #     hmc = hmac.new(str(peer_pub_key).encode(), message.encode(), hash_function)
        #     digest = hmc.hexdigest()
        elif hash_choice == 'SHA3':
            hash_function = SHA3_256.new()
            hash_function.update(message.encode())
            digest = hash_function.hexdigest()
        sendlist.insert(0, digest)
        #print('sending hash', digest)
        str = rsa.encrypt(message.encode('utf8'), peer_pub_key)
        sendlist.insert(1, str)
        client1.send(pickle.dumps(sendlist))
    elif enc_choice == 'AES':
        digest = ''
        sendlist = []
        str = client1.recv(2048)
        msg = pickle.loads(str)
        message = msg[1]
        iv = message[:24]
        iv = b64decode(iv)
        cipher = message[24:]
        cipher = b64decode(cipher)
        temp = aes_password[:16]
        aes = AES.new(temp.encode(), AES.MODE_CBC, iv)
        pt = aes.decrypt(cipher)
        pt = unpad(pt, AES.block_size)
        print(client2_name, ':', pt.decode())

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

        message = input('You:')
        if message == 'BYE' or message == 'bye':
            message = "Leaving Chat Room, Goodbye!"
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
            client1.send(pickle.dumps(sendlist))
            print('')
            break
        temp = aes_password[:16]
        aes = AES.new(temp.encode(), AES.MODE_CBC)
        cipher = aes.encrypt(pad(message.encode(), AES.block_size))
        iv = b64encode(aes.iv).decode('utf-8')
        cipher = b64encode(cipher).decode('utf-8')
        written = iv+cipher

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
        sendlist.insert(1, written)
        client1.send(pickle.dumps(sendlist))
    elif enc_choice == 'DES':
        str = client1.recv(2048)
        msg = pickle.loads(str)
        message = msg[1]
        dec = DES3.new(des_password.encode(), DES3.MODE_OFB, privkey)
        ptext = dec.decrypt(message)
        print(client2_name, ":", ptext.decode())

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
        if msg[0] != digest:
            print('Hashes not matched!\nTampering detected!')

        message = input('You: ')
        if message == "BYE" or message == "bye":
            message = "Leaving Chat Room, Goodbye!"
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
            client1.send(pickle.dumps(sendlist))
            print('')
            break

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
        client1.send(pickle.dumps(sendlist))
    else:
        message = client1.recv(1024)
        message = message.decode()
        print(client2_name, ":", message)
        message = input('You: ')
        if message == "BYE" or message == "bye":
            message = "Leaving Chat Room, Goodbye!"
            client1.send(message.encode())
            print('')
            break
        client1.send(message.encode())
    # if message == "BYE" or message == "bye":
    #     message = "Leaving Chat Room, Goodbye!"
    #     if enc_choice == 'RSA':
    #         message = rsa.encrypt(message.encode('utf8'), peer_pub_key)
    #         client1.send(message)
    #     else:
    #         client1.send(message.encode())
    #     print("\n")
    #     break


# str = client1.recv(2048)
# key = pickle.loads(str)
# msg = 'hello'.encode('utf8')
# sectext = rsa.encrypt(msg, key)
# client1.send(pickle.dumps(sectext))


# (pub, priv) = rsa.newkeys(512)
# client2.send(pickle.dumps(pub))
# str = client2.recv(1024)
# msg = pickle.loads(str)
# ct = rsa.decrypt(msg, priv)
# print(ct.decode('utf8'))
