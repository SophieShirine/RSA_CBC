# -----------------------------------------------------------
# demonstrates the exchange of a private message from one persone (Bob)
# to another (Alice), using RSA and CBC crypting process
# This program is not aimed for industrial use
#
# (C) 2021 Sophie Teimournia
# -----------------------------------------------------------

import utils
import time


def home_mod_exp(x, y, n):
    """
        Modular exponentiation function x^y%n
        :param x: integer
        :param y: integer
        :param n: integer
        :return : integer result
    """

    result = 1

    while y > 0:
        if y % 2 == 1:
            result = (result * x) % n
        x = (x * x) % n
        y = y // 2

    return result


def home_euclide(y, b):
    """
        Euclid algorithm
        :param y: integer
        :param b: integer
        :return : integer
    """
    (r, nouvr, t, nouvt) = (y, b, 0, 1)

    while nouvr > 1:
        q = (r // nouvr)
        (r, nouvr, t, nouvt) = (nouvr, r % nouvr, nouvt, t - (q * nouvt))

    return nouvt % y


def home_cbc_encrypt(msg, key):
    """
        Crypting function of cbc
        :param msg: message to encrypt in hexadecimal
        :param key: key[0] = e, key[1] = n
        :return : list crypted
    """

    # key values
    e = key[0]
    n = key[1]

    c = decim_vect  # vector used at each iteration

    msg_chunks = []  # array of strings, containing the message sliced in chunks of same size
    crypted = []  # array of integers, containing the crypted value of each chunk

    # SLICE THE MESSAGE IN CHUNK OF SAME SIZE
    for i in range(len(msg), 0, - chunks_size):
        if i - chunks_size < 0:
            full_block = ("\0" * (chunks_size - i)) + msg[0:i]
            msg_chunks.insert(0, full_block)
        else:
            msg_chunks.insert(0, msg[i - chunks_size:i])

    # CRYPT EACH CHUNK
    for bloc in msg_chunks:
        decim_chunk = utils.home_string_to_int(bloc)  # get the decimal value
        xor = decim_chunk ^ c
        crypted.append(home_mod_exp(xor, e, n))
        c = home_mod_exp(xor, e, n)

    return crypted


def home_cbc_decrypt(crypted_msg, key):
    """
        Function decoding a message using cbc
        :param crypted_msg: a list of crypted chunks
        :param key: key[0] = e, key[1] = n
        :return : string decrypted
    """

    # key values
    d = key[0]
    n = key[1]

    c = decim_vect
    decrypted = ""  # decrypted message

    # DECODING
    for bloc in crypted_msg:
        decrypt_chunk = home_mod_exp(bloc, d, n)
        xor = decrypt_chunk ^ c
        decrypted = decrypted + utils.home_int_to_string(xor)
        c = bloc

    return decrypted


def cbc_test_case():
    """CBC test Case"""

    # BOB ENTERS A MESSAGE
    message = utils.long_message()
    start = time.time()

    # CRYPT THAT MUSIQUE USING ALICE'S PUBLIC KEY
    crypted_message = home_cbc_encrypt(message, (ea, na))

    # BOB SENDS THE MESSAGE
    print("\n \t##### Bob sent the message to Alice ! #####\n")

    # ALICE DECODES THE MESSAGE
    decrypted_message = home_cbc_decrypt(crypted_message, (da, na))
    print("Alice decodes the message and gets : \n" + str(decrypted_message))

    print("The time used to execute this is given below")
    end = time.time()
    print(end - start)


def rsa_test_case():
    """RSA test Case"""

    # BOB ENTERS A MESSAGE
    message = utils.mot10char()

    # CHANGE IT INTO A DECIMAL VALUE
    decimal_message = utils.home_string_to_int(message)
    print("1) The decimal value of secret is :  " + str(decimal_message))

    # CRYPT THE MESSAGE WITH ALICE'S PUBLIC KEY
    chiff_message = home_mod_exp(decimal_message, ea, na)
    print("2) Here is the crypted message : \n" + str(chiff_message))

    # COMPUTE THE MESSAGE'S HASH
    Bhachis = utils.home_hash_256(message)
    print("3) Here is the message's hash in decimal value :\n" + str(Bhachis))

    # CALCULATE THE SIGNATURE WITH THE PRIVATE KEY AND THE HASH
    signature = home_mod_exp(Bhachis, db, nb)
    print("4) Here is the signature obtained with the hash and the private key :\n" + str(signature))

    # BOB SENDS THE CRYPTED MESSAGE AND HIS SIGNATURE
    print("\n \t##### Bob sent the message and the signature ! #####\n")

    # ALICE DECODES THE MESSAGE
    dechiff_int = home_mod_exp(chiff_message, da, na)
    dechiff_message = utils.home_int_to_string(dechiff_int)
    print("1) Alice decodes the message and gets : \n" + str(dechiff_message))

    # ALICE DECODES THE SIGNATURE
    dechiff_signature = home_mod_exp(signature, eb, nb)
    print("2) Alice decodes the signature and gets : \n" + str(dechiff_signature))

    # ALICE HASH THE MESSAGE
    Ahachis = utils.home_hash_256(dechiff_message)
    print("3) Alice hashes the decrypted message and gets :\n" + str(Ahachis))

    # ALICE CHECKS IF THE SIGNATURE IS SIMILAR TO THE HASH
    if Ahachis - dechiff_signature == 0:
        print("\n\t##### Alice : « All good, Bob sent me the following message : " + str(dechiff_message) + " »")
    else:
        print("\n\t##### Alice : « Ouch... The signature doesn't go with Bob's message ! » \n")


# ALICE KEY
x1a = 59491385193988702457395767302826768908819578825613995679824307137199289878110765336234096122020538234539
x2a = 93629984011441362134159953033812389031433862201745309946147572649619757469843159468180335428479712932013
na = x1a * x2a  # n
phia = ((x1a - 1) * (x2a - 1)) // utils.home_pgcd(x1a - 1, x2a - 1)
ea = 17
da = home_euclide(phia, ea)

# BOB KEY
x1b = 20989494734566712640077598190855094400047634433405507639039008829569087182016762802141971886436081034299
x2b = 58178100075428377506708174075007280674533193827166138377953839487354230052508187949993937621428818923049
nb = x1b * x2b
phib = ((x1b - 1) * (x2b - 1)) // utils.home_pgcd(x1b - 1, x2b - 1)
eb = 23
db = home_euclide(phib, eb)

# VECTOR VALUE FOR CBC
vect = "f-_fdV5Jdsfme"
decim_vect = utils.home_string_to_int(vect)

chunks_size = 3

if __name__ == '__main__':
    print("Bob's public key : (" + str(eb) + "," + str(nb) + ")")
    print("Bob's private key : db = " + str(db))

    print("Alice public key ': (" + str(ea) + "," + str(na) + ")\n")

    print("Which test do you want to try ?\n1 - RSA\n2 - CBC")
    choice = input()

    if choice == "1":
        rsa_test_case()
    elif choice == "2":
        cbc_test_case()
    else:
        print("Error")
