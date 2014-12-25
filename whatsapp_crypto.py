import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import binascii
import tempfile
from io import BytesIO
import gzip
import os
import sqlite3
import csv
import time
import datetime

OUTPUT_PATH = 'output/'

def extract_key_iv(s):
    s = binascii.hexlify(s)
    return  binascii.unhexlify(s[252:316]), binascii.unhexlify(s[220:252])

def aes_decrypt(enc, key, iv):
    # fixed key length
    cipher = AES.new(key, AES.MODE_CBC, iv)
    result = cipher.decrypt(enc)
    return result

def crypt8_to_sql(key_file_path, data_file_path):
    key_data = None
    db = OUTPUT_PATH+'msgstore.db'
    csv_name = OUTPUT_PATH+'result.csv'
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

        with open(db, 'wb') as output_file:
            output_file.write(data)
        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute("SELECT key_remote_jid, received_timestamp, data FROM messages")
        with open(csv_name, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            csvwriter.writerow(['Phone Number', 'Received Time', 'Message'])
            for row in c.fetchall():
                tmp = list(row)
                timestamp = tmp [1]
                tmp[1] = datetime.datetime.fromtimestamp(timestamp / 1000.0)
                csvwriter.writerow(tmp)
    os.remove(tmp_file)
if __name__ == "__main__":
    if not os.path.exists(OUTPUT_PATH):
        os.makedirs(OUTPUT_PATH)
    key_file = sys.argv[1]
    data_file = sys.argv[2]
    crypt8_to_sql(key_file, data_file)


