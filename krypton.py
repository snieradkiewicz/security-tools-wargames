import base64
import binascii
from tools import cryptotools
from tools import assets
import string

def level0():
    base = 'S1JZUFRPTklTR1JFQVQ='
    unbase = base64.b64decode(base)
    print(unbase)
    return True


def level1():
    encrypted = 'YRIRY GJB CNFFJBEQ EBGGRA'
    cryptotools.rot_range(encrypted)
    return True


def level2():
    cesar = bytearray(b'MNOPQRSTUVWXYZACBDEFGHIJKLMNOPQRSTUVWXYZACBDEFGHIJKL')
    cesar_plain = bytearray(b'ABCDEFGHIJKLMNOQPRSTUVWXYZabcdefghijklmnoqprstuvwxyz')
    encrypted = bytearray(b'OMQEMDUEQMEK')
    decrypted = bytearray(b'')
    for i in range(0, len(encrypted)):
        decrypted += chr(cesar_plain[cesar.find(encrypted[i])]).encode('ascii')

    print(decrypted)
    return True


def level3():
    data = bytearray(b'')
    with open("tmp/krypton_found1.txt", "r") as file:
        for line in file:
            data += bytes(line.encode("ascii"))

    with open("tmp/krypton_found2.txt", "r") as file:
        for line in file:
            data += bytes(line.encode("ascii"))

    with open("tmp/krypton_found3.txt", "r") as file:
        for line in file:
            data += bytes(line.encode("ascii"))
    # remove meaningless spaces
    data = data.replace(b' ', b'')

    # count each letter frequency
    letters = bytearray(b'ABCDEFGHIJKLMNOQPRSTUVW')
    frequencies = list()
    data_len = len(data)
    for letter in letters:
        frequencies.append((chr(letter), data.count(letter)/data_len))
    print(frequencies)

    # sort frequencies by frequency descending
    def get_second(obj):
        return obj[1]

    frequencies.sort(key=get_second, reverse=True)
    print(frequencies)

    # generate keys
    key_generator = list()
    i = 0
    for key, val in assets.Assets.english_letter_frequency.items():
        key_generator.append(list())
        for j in range(0, len(frequencies)):
            if frequencies[j][1] * 1.5 >= val >= frequencies[j][1] * 0.667 or i+1 >= j >= i-1:
                key_generator[i] += [str(frequencies[j][0]).encode('ascii')]
        i += 1

    print('Key generator: ' + str(key_generator))

    max_lens = list()
    for options in key_generator:
        max_lens.append(len(options))

    def inc_at_index(lst, max_lst, index=0):
        if lst[index] >= max_lst[index] - 1:
            if index == len(lst) - 1:
                return False
            else:
                inc_at_index(lst, max_lst, index + 1)
                return False
        else:
            lst[index] += 1
            for i in range(index+1, len(lst)):
                lst[i] = 0
            return True


    curr_indexes = list([0]*26)

    while True:
        curr_key = bytearray(b'')
        propkey = True
        for i in range(0, len(max_lens)):
            if not curr_key.__contains__(key_generator[i][curr_indexes[i]]):
                curr_key += key_generator[i][curr_indexes[i]]
                if i == len(max_lens) - 1:
                    propkey = True
            else:
                # print('inc fired for index: ' + str(i))
                inc_at_index(curr_indexes, max_lens, i)
                propkey = False
                break


        print(curr_key + b' ' + bytearray(str(curr_indexes).encode('ascii')))

        if propkey:
            print(curr_key)
            trans_table = data.maketrans(assets.Assets.english_letter_by_freq, curr_key)
            data.translate(trans_table)
            print(curr_key + b'   ' + data)
            if not inc_at_index(curr_indexes, max_lens):
                break


def main():
    levels = ('0', '1', '2', '3')

    print("Hi there!\n"
          "you've just run krypton (http://overthewire.org/wargames/krypton/) levels solutions. Not every level\n"
          "require a python solution, so this app will not help you with all of them. Anyway enjoy our stay.\n")

    print("Available levels solutions: " + str(levels).strip(' ()').replace("'", ""))
    level = input("Pick level to solve: ")
    level = level.lower().strip()

    if level == 'q':
        return 0

    if level in levels:
        if level == '0':
            level0()
        if level == '1':
            level1()
        if level == '2':
            level2()
        if level == '3':
            level3()
    else:
        print("Hey! There is no such level. Bye bye!")


if __name__ == '__main__':
    main()