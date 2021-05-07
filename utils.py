import hashlib
import binascii


def mot10char():  # entrer le secret
    secret = input("Donnez un secret de 10 caractères au maximum : ")
    while (len(secret) > 11):
        secret = input("C'est beaucoup trop long, 10 caractères S.V.P : ")
    return (secret)

def messageLong():
    secret = input("Donnez un message secret : ")
    while (len(secret) > 1000000000000000000000000):
        secret = input("C'est beaucoup trop long, 10 caractères S.V.P : ")
    return (secret)

def home_string_to_int(x):  # pour transformer un string en int
    z = 0
    for i in reversed(range(len(x))):
        z = int(ord(x[i])) * pow(2, (8 * i)) + z
    return (z)


def home_int_to_string(x):  # pour transformer un int en string
    txt = ''
    res1 = x
    while res1 > 0:
        res = res1 % (pow(2, 8))
        res1 = (res1 - res) // (pow(2, 8))
        txt = txt + chr(res)
    return txt


def home_hash(msg):
    hash0 = hashlib.md5(msg.encode(encoding='UTF-8', errors='strict')).digest()  # MD5 du message
    hash1 = binascii.b2a_uu(hash0)
    hash2 = hash1.decode()  # en string
    hash3 = home_string_to_int(hash2)
    return hash3


def home_hash_256(msg):
    #hash0 = hashlib.sha256(msg.encode('utf-8')).hexdigest()
    hash0 = hashlib.sha256(msg.encode(encoding='UTF-8',errors='strict')).digest()
    hash1 = binascii.b2a_uu(hash0)
    hash2 = hash1.decode()  # en string
    hash3 = home_string_to_int(hash2)
    return hash3

def home_pgcd(a, b):  # recherche du pgcd
    if b == 0:
        return a
    else:
        return home_pgcd(b, a % b)
