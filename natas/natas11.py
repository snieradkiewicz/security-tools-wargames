import base64
import binascii
from tools import cryptotools


def main():
    level = 11
    level_about = 'In this level you can see a sourcecode of vulnerable website, which is quite handy. In the source\n'\
                  'you can see that there are some information stored in cookie named "data". This information is\n' \
                  'JSON encoded associative array with element key "showpassword"  and other element with key\n' \
                  '"bgcolor". We need to change the value of the "showpassword" element from default "no" to "yes".\n' \
                  'From the sourcecode we can see that cookie value has been encrypted using xor with some censored\n'\
                  'key and then encoded using base64. To solve this level we need to get encrypted version of \n' \
                  'default cookie, xor it with our known cookie value to retrieve key, then modify the cookie and \n'\
                  'xor  modified cookie with extracted key. We need to remember that our data will be now longer \n' \
                  'than default data, so we need to check if key is shorten than default data and used repeatedly \n' \
                  'or figure out sth. else.'

    print("Hi there!\nyou've just run natas level " + str(level) +
          " (http://overthewire.org/wargames/natas/). Credentials are available in the secrets/credentials.py")
    print("\n" + level_about + "\n\n")

    # Real solution starts here :-)
    default_enc_cookie_b64 = b'ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw='
    default_cookie_plain = b'{"showpassword":"no","bgcolor":"#ffffff"}'

    # XORing encrypted cookie with its known plain version
    default_enc_cookie = base64.b64decode(default_enc_cookie_b64)
    key_ext = cryptotools.bytes_xor(default_enc_cookie, default_cookie_plain)

    print('Found expanded key: ' + str(key_ext))

    # we need to find size of a key now
    key_size = 0
    for size in (2, round(len(key_ext)/2)):
        if cryptotools.compare_bytearrays(key_ext[0:size], key_ext[size:size*2]):
            key_size = size
            break

    if key_size == 0:
        print('Cannot compute keysize, need to figure out sth more here!')
        return False

    key = key_ext[0:key_size]

    modified_cookie = default_cookie_plain.replace(b'"no"', b'"yes"')
    print("New cookie: " + str(modified_cookie.decode('ascii')))

    modified_cookie_enc = cryptotools.bytes_xor(modified_cookie, key)
    modified_cookie_enc_b64 = base64.b64encode(modified_cookie_enc)
    print("New modified cookie encoded and base64: " + str(modified_cookie_enc_b64))

    return True


if __name__ == '__main__':
    main()
