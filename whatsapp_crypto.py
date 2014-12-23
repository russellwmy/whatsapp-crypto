import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import binascii
import tempfile
from io import BytesIO
import gzip
import os

OUTPUT_PATH = 'output/'

def extract_key_iv(s):
    s = binascii.hexlify(s)
    return  binascii.unhexlify(s[252:316]), binascii.unhexlify(s[220:252])

def aes_decrypt(enc, key, iv):
    # fixed key length
    cipher = AES.new(key, AES.MODE_CBC, iv)
    result = cipher.decrypt(enc)
    return result

def export_to_sql(key_file_path, data_file_path):
    key_data = None
    with open(key_file_path, 'rb') as key_file:
        key_data = key_file.read()
    key, iv = extract_key_iv(key_data)

    data = None
    with open(data_file_path, 'rb') as data_file:
        data_file.seek(67)
        data = data_file.read()
    decrypted = aes_decrypt(data, key, iv)

    tmp_file = OUTPUT_PATH+'msgstore.db.gz'
    with open(tmp_file, 'wb') as output_file:
        output_file.write(decrypted)

    with open(tmp_file, 'rb') as input_file:
        buf = BytesIO(input_file.read())
        input_file.seek(0)
        buf.seek(-1,2)
        pad_bytes = ord(buf.read(1))
        buf.truncate(len(input_file.read()) - pad_bytes)
        buf.seek(0)
        tmp = gzip.GzipFile(fileobj=buf)
        data = tmp.read()

        with open(OUTPUT_PATH+'msgstore.db', 'wb') as output_file:
            output_file.write(data)
    os.remove(tmp_file)
if __name__ == "__main__":
    key_file = sys.argv[1]
    data_file = sys.argv[2]
    export_to_sql(key_file, data_file)


