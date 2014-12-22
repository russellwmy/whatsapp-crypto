import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import binascii


def extract_key_iv(s):
    s = binascii.hexlify(s)
    return  binascii.unhexlify(s[252:316]), binascii.unhexlify(s[220:252])

def aes_decrypt(enc, key, iv):
    # fixed key length
    # enc = binascii.hexlify(enc)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    result = cipher.decrypt(enc)
    return result

key_file = sys.argv[1]

key_data = None
with open(key_file, 'rb') as kf:
    key_data = kf.read()
key, iv = extract_key_iv(key_data)


data_file = sys.argv[2]
data = None
with open(data_file, 'rb') as df:
    data = df.read()

aes_decrypt(data, key, iv)

