"""
Based on the paper "A study on LG content lock and data aquisition from apps based on content lock function"
from Giyoon Kim, Myungseo Park, Jongsung, Kim
from 28 September 2021
Please use at your own advice. There are no error handlers.
"""

import base64
import binascii
import re
import sys
import os
import shutil
from hashlib import md5, sha1

# see https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def getword(hexvalue, index):
    return hexvalue[(index * 8):(index * 8 + 8)]

def multiple_hexxor(hex1, modifier):
    for i in range(0, 5):
        hex1[i] = ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a, b in zip(hex1[(modifier + i) % 5], hex1[i]))
    return hex1

def decryptlg(gmailadress, lgeflock):

    ###
    # Line 1 (these line numbers indicate the line numbers from algorithm 4 in the paper)
    # h1 is SHA1 of gmailadress and split into 5 sets
    # Grouped h1, h2 and h4 in 5 sets of 1 word / 4 bytes / 32 bits as strings

    # SHA1 of mailadress: (160-bit)
    h1_sha = sha1(gmailadress).hexdigest()
    # h1 is a list of 5 hexvalues as string
    h1 = []
    for i in range (0, 5):
        h1.append(getword(h1_sha, i))

    ###
    # Line 2 - 3
    # XOR of h1 with h1

    h1 = multiple_hexxor(h1, 2)

    # concatenate h1 for SHA1 and convert to hex
    h1_concat = ''.join(map(str, h1)).encode('utf-8')
    h1_realhex = bytearray.fromhex(h1_concat.decode('utf-8'))

    ###
    # Line 4
    # h2 is SHA1 of h1

    h2_sha = sha1(h1_realhex).hexdigest()
    h2 = []
    for i in range (0, 5):
        h2.append(getword(h2_sha, i))
    
    ###
    # Line 5 - 6
    # XOR of h2 with h2

    h2 = multiple_hexxor(h2, 4)

    # concatenate h2 for SHA1 and convert to hex
    h2_concat = ''.join(map(str, h2)).encode('utf-8')
    
    ###
    # Line 7
    # h3 is concatenation of parts of h2 and lgeflock

    h2_16_concat = h2_concat[:32]
    # h3 is not a hex like h1 and h2 but a string
    h2_16_concat = bytearray.fromhex(h2_16_concat.decode('utf-8'))
    h3 = (h2_16_concat + lgeflock)

    ###
    # Line 8
    # dk is the first 4 words of SHA1 of h3 (128 bits = 16 bytes = 4 words)

    dk_sha = sha1(h3).hexdigest()
    dk = dk_sha[:32]
    return dk

    """
    # LGEID is unimportant because we don't need the gmailaddress to
    # match for authentication because we want to retrieve our own files
    # this part of the code is not tested
    
    ###
    # Line 9
    # h4 is SHA1 of h2

    h4_sha = sha1(h2_hex).hexdigest()
    h4 = []

    for i in range (0, 5):
        h4.append(getword(h4_sha, i))

    ###
    # Line 10 - 11
    # XOR of h4 with h4

    h4 = multiple_hexxor(h4, 3)

    # concatenate h4 for SHA1
    h4_concat = ''.join(map(str, h4)).encode('utf-8')
    h4_hex = str(int(h4_concat, 16)).encode('utf-8')
    h4_realhex = bytearray.fromhex(h4_concat.decode('utf-8'))

    ###
    # Line 12
    # LGEID is base64 of h4
    
    lgeid = base64.b64encode(h4_hex)
    lgeid_decoded = base64.b64decode(lgeid)
    return (dk, lgeid.decode('utf-8'))
    """

def get_lgeflock_iv_imagestart(image_path):

    # open encrypted image as bytes
    cipher_file = open(image_path, "rb")
    cipher_header = cipher_file.read(1024) # read only first 1 KB
    cipher_file.close()

    # define regex search strings
    lgeflock_searchstring = b'lge/flock(L[0-9\-_]+@lge.com)'
    lgeid_searchstring = b'LGEID2.+\r\n'

    # look up lgeflock:
    re_lgeflock = re.compile(lgeflock_searchstring)
    result_lgeflock = re_lgeflock.search(cipher_header)
    lgeflock = result_lgeflock.group(1)

    # lookup position of iv
    suche = re.compile(lgeid_searchstring)
    result = suche.search(cipher_header)
    startbyte, endbyte = result.regs[0]

    # iv is found with length of 16 bytes
    iv = cipher_header[endbyte:endbyte + 16]
    
    # image starts at next byte after iv
    imagestartbyte = endbyte + 16

    return lgeflock, iv, imagestartbyte

def main():

    # your gmail address on your phone when the files have been encrypted
    gmail = b'yourgmailaddress@gmail.com'
    
    # folders of encrypted and decrypted files
    encrypt_dir = './encrypted'
    decrypt_dir = ''

    # the name of a single encrypted file with and without .dm suffix
    image_filename = sys.argv[1]
    image_filename_decrypted = image_filename.strip('.dm')

    image_path_encrypted = os.path.join(encrypt_dir, image_filename)
    image_path_decrypted = os.path.join(decrypt_dir, image_filename_decrypted)
    
    print("Start decrypting file", image_filename)

    # get strings from the file header
    lgeflock, iv, imagestartbyte = get_lgeflock_iv_imagestart(image_path_encrypted)
    print("lgeflock:", lgeflock.decode('utf-8'))
    
    # iv is stored as byte array with length of 16 bytes
    # iv_hex is stored as hex string with length of 32 chars
    iv_hex = binascii.hexlify(bytearray(iv))
    print("iv:", iv_hex)

    # open encrypted image as bytes
    cipher_file = open(image_path_encrypted, "rb")
    # skip header and iv to image start
    cipher_file.seek(imagestartbyte)
    # read from seek to end
    cipher_body = cipher_file.read()
    cipher_file.close()
    print("File information read successfully")

    # run algorithm 4 from paper
    print("Retrieving decryption key")
    dk = decryptlg(gmail, lgeflock)
    print("Decryption key:", dk)

    key = bytes.fromhex(dk)
    print("Applying decryption key")
    
    # AES decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(cipher_body)
    print("Image decrypted")

    # save as image without .dm extension
    out_file = open(image_path_decrypted, "wb")
    out_file.write(plaintext)
    out_file.close()
    print("Image saved as", image_filename_decrypted, "\n")

    # move decrypted image into decrypted subfolder
    shutil.move(image_path_decrypted, 'decrypted/' + image_path_decrypted)

if __name__ == "__main__":
    main()
