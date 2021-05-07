import utils
import time

'''@brief : exponentiation modulaire
@param : int x,y,n
@return : int result
'''
def home_mod_exp(x, y, n):
    result = 1

    while y > 0:
        if y % 2 == 1:
            result = (result * x) % n
        x = (x * x) % n
        y = y // 2
    return result

'''@brief : algorithme d'euclide
@param : int y,b
@return : int nouvt%y
'''
def home_euclide(y, b):
    (r, nouvr, t, nouvt) = (y, b, 0, 1)

    while nouvr > 1:
        q = (r // nouvr)
        (r, nouvr, t, nouvt) = (nouvr, r % nouvr, nouvt, t - (q * nouvt))

    return nouvt % y

'''@brief : fonction qui crypte un message en utilisant le cbc
@param : string msg, string init_vect, int key[2]
@return : list crypted
'''
def home_cbc_encrypt(msg, key):
    # valeur des clés
    e = key[0]
    n = key[1]

    c = decim_vect  # valeur du vecteur utilise pour le xor a chaque iteration

    blocs_msg = []  # tableau de string contenant le msg coupés en blocs
    crypted = []  # tableau d'entiers contenant les valeurs cryptees de chaque bloc

    # DECOUPAGE DU MESSAGE EN BLOCS DE TAILLE IDENTIQUE
    for i in range(len(msg), 0, -tailleBlocs):
        if i - tailleBlocs < 0:
            full_block = ("\0" * (tailleBlocs - i)) + msg[0:i]
            blocs_msg.insert(0, full_block)
        else:
            blocs_msg.insert(0, msg[i - tailleBlocs:i])

    # CRYPTAGE
    for bloc in blocs_msg:
        # calculer le xor
        decim_bloc = utils.home_string_to_int(bloc)
        xor = decim_bloc ^ c

        # stocker la valeur chiffree
        crypted.append(home_mod_exp(xor, e, n))
        # on change le vecteur
        c = home_mod_exp(xor, e, n)

    return crypted

'''@brief : fonction qui décrypte un message en utilisant le cbc
@param : list crypted_msg, string init_vect, int key[2]
@return : string decrypted
'''
def home_cbc_decrypt(crypted_msg, key):
    # valeur des clés
    d = key[0]
    n = key[1]

    c = decim_vect  # valeur du vecteur utilise pour le xor a chaque iteration
    decrypted = ""

    # DECRYTER
    for bloc in crypted_msg:
        decrypt_bloc = home_mod_exp(bloc, d, n)
        xor = decrypt_bloc ^ c  # valeur decimale decryptee
        decrypted = decrypted + utils.home_int_to_string(xor)
        c = bloc

    return decrypted


def home_cipher_block_chaining(msg, key):
    # valeur des clés
    e = key[0]
    n = key[1]
    d = key[2]

    c = decim_vect  # valeur du vecteur utilise pour le xor a chaque iteration

    blocs_msg = []  # tableau de string contenant le msg coupés en blocs
    crypted = []  # tableau d'entiers contenant les valeurs cryptees de chaque bloc
    decrypted = ""

    # DECOUPAGE DU MESSAGE EN BLOCS DE TAILLE N (ICI N = 3)
    for i in range(len(msg), 0, -tailleBlocs):
        if i - tailleBlocs < 0:
            full_block = ("\0" * (tailleBlocs - i)) + msg[0:i]
            blocs_msg.insert(0, full_block)
        else:
            blocs_msg.insert(0, msg[i - tailleBlocs:i])

    # CRYPTAGE
    for bloc in blocs_msg:
        # calculer le xor
        decim_bloc = utils.home_string_to_int(bloc)
        xor = decim_bloc ^ c

        # stocker la valeur chiffree
        crypted.append(home_mod_exp(xor, e, n))
        # on change le vecteur
        c = home_mod_exp(xor, e, n)

    c = decim_vect
    # DECRYTER
    for bloc in crypted:
        decrypt_bloc = home_mod_exp(bloc, d, n)
        xor = decrypt_bloc ^ c  # valeur decimale decryptee
        # decrypted.append(utils.home_int_to_string(xor))
        decrypted = decrypted + utils.home_int_to_string(xor)
        c = bloc

    print(decrypted)

'''@brief : test case of the cbc method
'''
def cbc_test_case():
    # ENTRER LE MESSAGE DE BOB
    message = utils.message_long()
    start = time.time()

    # CHIFFRER CE MESSAGE AVEC LA CLE PUBLIQUE DE ALICE
    crypted_message = home_cbc_encrypt(message, (ea, na))

    # BOB ENVOIE LE MESSAGE
    print("\n \t##### Bob envoie le message à Alice ! #####\n")

    # ALICE DECHIFFRE LE MESSAGE
    decrypted_message = home_cbc_decrypt(crypted_message, (da, na))
    print("Alice déchiffre le message de Bob et obtient : \n" + str(decrypted_message))

    print("The time used to execute this is given below")
    end = time.time()
    print(end - start)

'''@brief : test case of the rsa method
'''
def rsa_test_case():
    # ENTRER LE MESSAGE DE BOB
    message = utils.mot10char()

    # TRANSFORMER EN NOMBRE DECIMAL
    decimal_message = utils.home_string_to_int(message)
    print("1) La version en nombre décimal du secret est " + str(decimal_message))

    # CHIFFRER AVEC LA CLE PUBLIQUE D'ALICE
    chiff_message = home_mod_exp(decimal_message, ea, na)
    print("2) Voici le message chiffré avec la clé publique de Alice : \n" + str(chiff_message))

    # ON CALCULE LE HASH DU MESSAGE
    Bhachis = utils.home_hash_256(message)
    # Bhachis = utils.home_hash(message)
    print("3) Voici le hash en nombre décimal du message : \n" + str(Bhachis))

    # ON CALCULE ENSUITE LA SIGNATURE AVEC LA CLE PRIVEE ET LE HASH
    signature = home_mod_exp(Bhachis, db, nb)
    print("4) Voici la signature obtenue avec la clé privée de Bob et le hash :\n" + str(signature))

    # BOB ENVOIE LE MESSAGE CHIFFRE ET LA SIGNATURE
    print("\n \t##### Bob envoie le message et sa signature à Alice ! #####\n")

    # ALICE DECHIFFRE LE MESSAGE
    dechiff_int = home_mod_exp(chiff_message, da, na)
    dechiff_message = utils.home_int_to_string(dechiff_int)
    print("1) Alice déchiffre le message et obtient : \n" + str(dechiff_message))

    # ALICE DECHIFFRE LA SIGNATURE
    dechiff_signature = home_mod_exp(signature, eb, nb)
    print("2) Alice déchiffre la signature de Bob et obtient : \n" + str(dechiff_signature))

    # ALICE HASH LE MESSAGE QU'ELLE A OBTENU
    Ahachis = utils.home_hash_256(dechiff_message)
    # Ahachis = utils.home_hash(dechiffMessage)
    print("3) Alice hash le message qu'elle a déchiffré et obtient :\n" + str(Ahachis))

    # ALICE VERIFIE QUE LA SIGNATURE EST SIMILAIRE AU HASH
    if Ahachis - dechiff_signature == 0:
        print("\n\t##### Alice : « C'est bon, Bob m'a envoyé le message suivant : " + str(dechiff_message) + " »")
    else:
        print("\n\t##### Alice : « Aie... La signature ne colle pas avec le message de Bob ! » \n")


# CLE ALICE
x1a = 59491385193988702457395767302826768908819578825613995679824307137199289878110765336234096122020538234539
x2a = 93629984011441362134159953033812389031433862201745309946147572649619757469843159468180335428479712932013
na = x1a * x2a  # n
phia = ((x1a - 1) * (x2a - 1)) // utils.home_pgcd(x1a - 1, x2a - 1)
ea = 17  # exposant public
da = home_euclide(phia, ea)  # exposant privé

# CLE BOB
x1b = 20989494734566712640077598190855094400047634433405507639039008829569087182016762802141971886436081034299
x2b = 58178100075428377506708174075007280674533193827166138377953839487354230052508187949993937621428818923049
nb = x1b * x2b
phib = ((x1b - 1) * (x2b - 1)) // utils.home_pgcd(x1b - 1, x2b - 1)
eb = 23
db = home_euclide(phib, eb)

vect = "f-_fdV5Jdsfme"
decim_vect = utils.home_string_to_int(vect)
tailleBlocs = 3

if __name__ == '__main__':
    print("Clé publique de Bob : (" + str(eb) + "," + str(nb) + ")")
    print("Clé privé de Bob : db = " + str(db))

    print("Clé publique d'Alice ': (" + str(ea) + "," + str(na) + ")\n")

    print("Quelle test voulez-vous effectuer ?\n1 - RSA\n2 - CBC")
    choix = input()

    if choix == "1":
        rsa_test_case()
    elif choix == "2":
        cbc_test_case()
    else:
        print("Erreur")
