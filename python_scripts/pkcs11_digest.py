# This program gets the hash digest for a file
from PyKCS11 import LowLevel
import argparse

description = '''
Find the hash digest for a binary file.
Example:
./pkcs11_digest.py -p hunter2 -f /path/to/file.txt -m sha256'''
parser = argparse.ArgumentParser(description = description , formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-p', help='pin', required=True, dest='pin')
parser.add_argument('-f', help='file path', required=True, dest='filepath')
parser.add_argument('-m', help='mechanism (md5|sha1|sha224|sha256|sha384|sha512)', required=True, dest='mechanism')

args = parser.parse_args()
pin = bytes(args.pin, 'utf-8')
filepath = args.filepath
digest_mechanism = args.mechanism
if digest_mechanism == 'md5':
    hash_mechanism = LowLevel.CKM_MD5
elif digest_mechanism == 'sha1':
    hash_mechanism = LowLevel.CKM_SHA_1
elif digest_mechanism == 'sha224':
    hash_mechanism = LowLevel.CKM_SHA224
elif digest_mechanism == 'sha256':
    hash_mechanism = LowLevel.CKM_SHA256
elif digest_mechanism == 'sha384':
    hash_mechanism = LowLevel.CKM_SHA384
elif digest_mechanism == 'sha512':
    hash_mechanism = LowLevel.CKM_SHA512

# creates a CPKCS11Lib instance
p11_lib = LowLevel.CPKCS11Lib() 
lib_path = '/lib/softhsm/libsofthsm2.so'

# creates a ckintlist instance to store the slot_list
slot_list = LowLevel.ckintlist() 
rv = p11_lib.Load(lib_path)
print("%s : Load"%rv)

# get slot list
rv = p11_lib.C_GetSlotList(0, slot_list) 
print("%s : C_GetSlotList"%rv)

# start a session
session = LowLevel.CK_SESSION_HANDLE()
rv = p11_lib.C_OpenSession(slot_list[0], LowLevel.CKF_SERIAL_SESSION, session)
print("%s : C_OpenSession"%rv)

# login
rv = p11_lib.C_Login(session, LowLevel.CKU_USER, pin)
print("%s : C_Login"%rv)

# get data from a file
with open(filepath, 'r') as file:
    data = LowLevel.ckbytelist(bytes(file.read(), 'utf-8'))

digest = LowLevel.ckbytelist()
mechanism = LowLevel.CK_MECHANISM()
mechanism.mechanism = hash_mechanism

# initialize digest
rv = p11_lib.C_DigestInit(session, mechanism)
print('%s : C_DigestInit'%rv)

# call C_Digest to get the size of digest
rv = p11_lib.C_Digest(session, data, digest)
print('%s : C_Digest 1'%rv)

# call C_Digest a second time to fill it with the digest
rv = p11_lib.C_Digest(session, data, digest)
print('%s : C_Digest 2'%rv)

hex_digest = bytes(digest).hex()
print('digest : %s'%hex_digest)

# logout
rv = p11_lib.C_Logout (session)
print("%s : C_Logout"%rv)

# close session
rv = p11_lib.C_CloseSession(session)
print("%s : C_CloseSession"%rv)