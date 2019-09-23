import base64
from tools import cryptotools


def chapter1():
    hexstring1 = str("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    hexbytes = bytearray.fromhex(hexstring1)
    base64string = base64.b64encode(hexbytes)
    print(base64string)
    return True


def chapter2():
    import binascii
    hexstring2a = bytearray.fromhex("1c0111001f010100061a024b53535009181c")
    hexstring2b = bytearray.fromhex("686974207468652062756c6c277320657965")
    print(binascii.hexlify(bytearray(cryptotools.bytes_xor(hexstring2a, hexstring2b))))
    return True


def chapter3():
    hexstring3 = bytearray.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    decrypted = cryptotools.brute_single_byte_unxor(hexstring3)
    print(decrypted)
    return True


def chapter4():
    print("Try to unxor 60 chars lenght lines of file: \n")
    file = open("tmp/cryptopals_hashes.txt", "r")
    i = 1
    highest_score = 0.0
    best_result = ''
    linenr = 0
    for line in file:
        result = cryptotools.brute_single_byte_unxor(bytearray.fromhex(line))
        if (result[1] > highest_score):
            highest_score = result[1]
            best_result = result[2].decode("utf-8", errors='ignore')
            linenr = i
        i += 1
    print("Line: " + str(linenr) + "   Score: " + str(highest_score) + "     TEXT: " + best_result)
    file.close()
    return True


def chapter5():
    import binascii
    hexstring5a = bytes(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
    hexstring5b = bytes(b"ICE")

    print(hexstring5a)
    print(hexstring5b)

    print(binascii.hexlify(cryptotools.bytes_xor(hexstring5a, hexstring5b)).decode("utf-8"))
    return True


def chapter6():
    # CHAPTER 6
    hexstring6a = bytes(b"this is a test")
    hexstring6b = bytes(b"wokka wokka!!!")

    print(hexstring6a)
    print(hexstring6b)
    print(cryptotools.count_hamming_distance(hexstring6a, hexstring6b))

    base_plain = bytes(b"")
    with open("tmp/cryptopals_multibytexor.txt", "r") as file:
        for line in file:
            base_plain += bytes(line.encode("utf-8"))

    print("PLAIN: " + str(base_plain))

    decoded = bytes(base64.b64decode(base_plain))
    print("DECODED: " + str(decoded))

    crypt = cryptotools.CryptoTools(encrypted=decoded)

    key_lens = crypt.find_key_length(min_len=2, max_len=40, top_results=1)

    for key_len in key_lens[:]:
        key = crypt.find_key_multibyte_xor(key_len)
        print("The key is: " + str(key))
        crypt.print_in_columns(key_len)
    return True


def chapter7():
    # CHAPTER 7
    base64_plain = bytearray(b'')
    with open("tmp/cryptopals_7_aes128ecb.txt", "r") as file:
        for line in file:
            base64_plain += bytearray(line.encode("utf-8"))

    print("BASE 64 " + str(base64_plain))
    enc = bytearray(base64.b64decode(base64_plain))
    print("ENCRYPTED " + str(enc))
    crypt = cryptotools.CryptoTools(key=bytearray(b'YELLOW SUBMARINE'), encrypted=enc)
    crypt.decrypt_aes_128_ecb()
    print("DECRYPTED: " + str(crypt.get_decrypted()))
    return True


def chapter8():
    # CHAPTER 8 - detect AES 128 ECB
    with open("tmp/cryptopals_8_detect_aes128ecb.txt", "r") as file:
        i = 0
        for line in file:
            i += 1
            cipher = cryptotools.CryptoTools(encrypted=bytearray.fromhex(line))
            if cipher.is_aes_128_ecb():
                print("Found AES 128 ECB in line " + str(i) + "     content: \n" +
                      str([line[i:i+32] for i in range(0, len(line), 32)]))
    return True


def main():
    chapters = ('1', '2', '3', '4', '5', '6', '7', '8')

    print("Hi there!\n"
          "you've just run cryptopals (https://cryptopals.com/) chapters solutions. Not every chapter might require\n"
          "a python solution, so this app will not help you with all of them, but nearly all. Anyway enjoy our stay.\n")

    print("Available chapters solutions: " + str(chapters).strip(' ()').replace("'", ""))
    chapter = input("Pick chapters to solve: ")
    chapter = chapter.lower().strip()

    if chapter == 'q':
        return 0

    if chapter in chapters:
        if chapter == '1':
            chapter1()
        if chapter == '2':
            chapter2()
        if chapter == '3':
            chapter3()
        if chapter == '4':
            chapter4()
        if chapter == '5':
            chapter5()
        if chapter == '6':
            chapter6()
        if chapter == '7':
            chapter7()
        if chapter == '8':
            chapter8()
    else:
        print("Hey! There is no such chapter. Bye bye!")


if __name__ == '__main__':
    main()