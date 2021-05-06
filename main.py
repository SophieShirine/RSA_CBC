import utils

def home_pgcd(a, b):  # recherche du pgcd
    if b == 0:
        return a
    else:
        return home_pgcd(b, a % b)


def home_mod_exp(x, y, n):  # exponentiation modulaire
    result = 1

    while y > 0:
        if y % 2 == 1:
            result = (result * x) % n
        x = (x * x) % n
        y = y // 2
    return result


def home_euclide(y, b):
    (r, nouvr, t, nouvt) = (y, b, 0, 1)

    while nouvr > 1:
        q = (r // nouvr)
        (r, nouvr, t, nouvt) = (nouvr, r % nouvr, nouvt, t - (q * nouvt))

    return nouvt % y


# CLE ALICE
x1a = 59491385193988702457395767302826768908819578825613995679824307137199289878110765336234096122020538234539
x2a = 93629984011441362134159953033812389031433862201745309946147572649619757469843159468180335428479712932013
na = x1a * x2a  # n
phia = ((x1a - 1) * (x2a - 1)) // home_pgcd(x1a - 1, x2a - 1)
ea = 17  # exposant public
da = home_euclide(phia, ea)  # exposant privé

# CLE BOB
x1b = 20989494734566712640077598190855094400047634433405507639039008829569087182016762802141971886436081034299
x2b = 58178100075428377506708174075007280674533193827166138377953839487354230052508187949993937621428818923049
nb = x1b * x2b
phib = ((x1b - 1) * (x2b - 1)) // home_pgcd(x1b - 1, x2b - 1)
eb = 23
db = home_euclide(phib, eb)

if __name__ == '__main__':
    print("Clé publique de Bob : (" + str(eb) + "," + str(nb) + ")")
    print("Clé privé de Bob : db = " + str(db))

    print("Clé publique d'Alice ': (" + str(ea) + "," + str(na) + ")\n")

    # ENTRER LE MESSAGE DE BOB
    message = utils.mot10char()

    # TRANSFORMER EN NOMBRE DECIMAL
    decimalMessage = utils.home_string_to_int(message)
    print("1) La version en nombre décimal du secret est " + str(decimalMessage))

    # CHIFFRER AVEC LA CLE PUBLIQUE D'ALICE
    chiffMessage = home_mod_exp(decimalMessage, ea, na)
    print("2) Voici le message chiffré avec la clé publique de Alice : \n" + str(chiffMessage))

    # ON CALCULE LE HASH DU MESSAGE
    Bhachis = utils.home_hash_256(message)
    #Bhachis = utils.home_hash(message)
    print("3) Voici le hash en nombre décimal du message : \n" + str(Bhachis))

    # ON CALCULE ENSUITE LA SIGNATURE AVEC LA CLE PRIVEE ET LE HASH
    signature = home_mod_exp(Bhachis, db, nb)
    print("4) Voici la signature obtenue avec la clé privée de Bob et le hash :\n" + str(signature))

    # BOB ENVOIE LE MESSAGE CHIFFRE ET LA SIGNATURE
    print("\n \t##### Bob envoie le message et sa signature à Alice ! #####\n")

    # ALICE DECHIFFRE LE MESSAGE
    dechiffInt = home_mod_exp(chiffMessage, da, na)
    dechiffMessage = utils.home_int_to_string(dechiffInt)
    print("1) Alice déchiffre le message et obtient : \n" + str(dechiffMessage))

    # ALICE DECHIFFRE LA SIGNATURE
    dechiffSignature = home_mod_exp(signature, eb, nb)
    print("2) Alice déchiffre la signature de Bob et obtient : \n" + str(dechiffSignature))

    # ALICE HASH LE MESSAGE QU'ELLE A OBTENU
    Ahachis = utils.home_hash_256(dechiffMessage)
    #Ahachis = utils.home_hash(dechiffMessage)
    print("3) Alice hash le message qu'elle a déchiffré et obtient :\n" + str(Ahachis))

    # ALICE VERIFIE QUE LA SIGNATURE EST SIMILAIRE AU HASH
    if Ahachis - dechiffSignature == 0:
        print("\n\t##### Alice : « C'est bon, Bob m'a envoyé le message suivant : " + str(dechiffMessage) + " »")
    else:
        print("\n\t##### Alice : « Aie... La signature ne colle pas avec le message de Bob ! » \n")
