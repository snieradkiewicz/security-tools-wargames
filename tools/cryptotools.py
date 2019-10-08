import base64
from tools import assets
from tools import aes

def evaluate_english_score(message, message_contains_words=False):
    text = str(message.decode("utf-8", errors='ignore')).upper()
    score = 0.0
    # use proper dictionary depends if you expect to find whole words in message
    if message_contains_words:
        english_letter_frequency = assets.Assets().english_letters_and_words_frequency
    else:
        english_letter_frequency = assets.Assets().english_letter_frequency
    # calculate score by multiplying frequency by dictionary element occurrences
    for letter, freq in english_letter_frequency.items():
        score += freq * text.count(str(letter))
    # substract from score if message contain non-printable characters
    for letter in text:
        if not letter.isprintable() and letter != "\x0a" and score > -100:
            score -= 10.0
    return score


def count_hamming_distance(set1, set2):
    result = bytearray()
    count = 0
    i = 0
    # count number of set bytes in xored bytes from set1 and set2. Limited to shorten of set1, set2
    while i < len(set1) and i < len(set2):
        result.append(set1[i] ^ set2[i])
        count += bin(set1[i] ^ set2[i])[2:].count("1")
        i += 1
    return count


def find_n_best_results(all_results, top_results):
    results = all_results
    recently_added_score = -1.0
    recently_added_key = -1
    best_results = []
    # loop /top_results/ times
    for top in range(0, top_results):
        tmp_val = -1.0
        tmp_key = 0
        # pick next best result
        for key, val in results.items():
            if (val >= recently_added_score and key != recently_added_key) and val < tmp_val or tmp_val == -1:
                tmp_val = val
                tmp_key = key
        recently_added_key = tmp_key
        recently_added_score = tmp_val
        best_results.append(recently_added_key)
    return best_results


def bytes_xor(hexbytes1: bytes, hexbytes2: bytes):
    hexbytes1 = bytearray(hexbytes1)
    length = len(hexbytes2)
    # iterate through every byte and do xor
    for i in range(0, len(hexbytes1)):
        hexbytes1[i] = hexbytes1[i] ^ hexbytes2[i % length]
    return hexbytes1


def brute_single_byte_unxor(message):
    max_score = -10000000
    best_char = bytes()
    best_xored_string = bytes()
    # Iterate for each possible byte
    for i in range(0, 256):
        x = bytes([i])
        xored_string = bytes(bytes_xor(message, x))
        current_score = evaluate_english_score(xored_string)
        if current_score > max_score:
            max_score = current_score
            best_char = x
            best_xored_string = xored_string
        cs2 = current_score / len(message)
    return best_char, max_score, bytes(bytes_xor(message, best_char)), best_xored_string


def rot_range(msg, min = 1, max= 26):
    for i in range(min, max):
        message = bytearray(msg.encode('ascii'))
        for j in range(0, len(message)):
            if 90 >= int(message[j]) >= 65:
                message[j] = (((int(message[j]) + i) - 65) % 26) + 65
            else:
                if 122 >= int(message[j]) >= 97:
                    message[j] = (((int(message[j]) + i) - 97) % 26) + 97
        print("For rot: " + str(i) + " the message is : " + str(message))


def compare_bytearrays(array1, array2):
    if len(array1) != len(array2):
        return False
    for i in range(0, len(array1)):
        if array1[i] != array2[i]:
            return False
    return True


class CryptoTools:
    def __init__(self, key=bytes(), message=bytes(), encrypted=bytes()):
        self.__key = key
        self.__message = message
        self.__encrypted = encrypted

    def get_encrypted(self):
        return self.__encrypted

    def get_message(self):
        return self.__message

    def get_decrypted(self):
        return self.get_message()

    def find_key_length(self, min_len=2, max_len=40, fragments=4, top_results=3):
        """
        Calculate /top_results/ number of most probable key lengths
        :param min_len: minimum length of key
        :param max_len: maximum length of key
        :param fragments: maximum fragments to compute (usually more is better)
        :param top_results: number of returning results
        :return: ARRAY of most probable key lengths
        """
        encrypted = self.__encrypted
        key_size = min_len
        min_distance = -1.0
        results = dict()
        # probing encrypted message for key lengths from range(min_len, max_len)
        while key_size <= max_len:
            if len(encrypted) < (key_size * fragments):
                if fragments > 2:
                    fragments -= 1
                    continue
                else:
                    print("Data stream is too short. Stopped at " + str(fragments)
                          + "fragments with key_size: " + str(key_size))
                    break
            frags = [encrypted[0:key_size]]
            # slice encrypted to /fragments/ number of blocks
            for j in range(2, fragments + 1):
                frags.append(encrypted[key_size * (j - 1):key_size * j])
            count = 0
            distance = 0
            # calculate and sum up hamming distance between each sliced blocks
            for i in range(0, fragments):
                for j in range(i + 1, fragments):
                    distance += count_hamming_distance(bytes(frags[i]), bytes(frags[j]))
                    count += 1
            # normalize hamming distance sum by dividing it by mutations and key size
            score = distance / count / key_size
            if min_distance < 0 or score < min_distance:
                min_distance = score
            results[key_size] = score
            key_size += 1
            frags.clear()
        # find n best results
        best_results = find_n_best_results(results, top_results)
        return best_results

    def find_key_multibyte_xor(self, key_len):
        """
        find key for given key length

        :param key_len: length of a key (in bytes)
        :return:
        """
        encrypted = self.__encrypted
        # initialize table of size of keylen to store each block in it
        blocks = []
        for i in range(0, key_len):
            blocks.append(bytearray())
        # reorder encrypted to each n'th % keysize byte go to its block
        for i in range(0, len(encrypted)):
            blocks[i % key_len].append(encrypted[i])
        key = bytes(b"")
        for block in blocks:
            res = brute_single_byte_unxor(bytes(block))
            key += res[0]
        self.__key = key
        return key

    def is_key_and_message_plain_ascii(self):
        """
        Check if key and message are both plaintext (ASCII) so each byte of key and message is in range (\x00 - \x7f)
        then most significant bit of each byte in key would be unset (0) - so XOR of it is also unset (0).
        :return: Returns True if so, otherwise False
        """
        encrypted = self.__encrypted
        for byte in encrypted:
            calc = byte & int('10000000', 2)
            if calc == int('10000000', 2):
                return False
        return True

    def print_in_columns(self, key_len):
        zerofill = len(str(key_len))
        key = self.find_key_multibyte_xor(key_len)
        result = bytes_xor(self.get_encrypted(), key).decode(encoding='utf-8', errors='ignore').replace('\n', ' ')
        for i in range(0, len(result), key_len):
            line = result[i:i + key_len].replace('\n', ' ')
            print(str(len(line)).zfill(zerofill) + ' : ' + line)

    def encrypt_aes_128_ecb(self):
        self.__encrypted = aes.encrypt(self.__message, self.__key)

    def decrypt_aes_128_ecb(self):
        self.__message = aes.decrypt(self.__encrypted, self.__key)

    def is_aes_128_ecb(self):
        return aes.detect_aes_128_ecb(self.__encrypted, 128)
