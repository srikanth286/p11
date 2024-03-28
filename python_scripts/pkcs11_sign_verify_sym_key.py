# This program performs a sign and a verify with a symmetric AES key and objects
from PyKCS11 import LowLevel
import argparse

description = '''
Perform a sign and verify using a symmetric key or an object
Example:
python3 pkcs11_sign_verify_sym_key.py -p hunter2 -k key_name -f /path/to/file.txt -m sha256'''
parser = argparse.ArgumentParser(description = description , \
    formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-p', help='pin', required=True, dest='pin')
parser.add_argument('-k', help='key/object name', required=True, dest='key_name')
parser.add_argument('-f', help='file path', required=True, dest='filepath')
parser.add_argument('-m', \
    help='mechanism (sha1|sha224|sha256|sha384|sha512)', \
    required=True, dest='mechanism')

args = parser.parse_args()
pin = bytes(args.pin, 'utf-8')
key_name = args.key_name
filepath = args.filepath
digest_mechanism = args.mechanism
if digest_mechanism == 'sha1':
    hash_mechanism = LowLevel.CKM_SHA_1_HMAC
elif digest_mechanism == 'sha224':
    hash_mechanism = LowLevel.CKM_SHA224_HMAC
elif digest_mechanism == 'sha256':
    hash_mechanism = LowLevel.CKM_SHA256_HMAC
elif digest_mechanism == 'sha384':
    hash_mechanism = LowLevel.CKM_SHA384_HMAC
elif digest_mechanism == 'sha512':
    hash_mechanism = LowLevel.CKM_SHA512_HMAC

# creates a CPKCS11Lib instance
p11_lib = LowLevel.CPKCS11Lib() 
lib_path = '/lib/softhsm/libsofthsm2.so'

# creates a ckintlist instance to store the SlotList 
slotList = LowLevel.ckintlist() 
rv = p11_lib.Load(lib_path)
print("%s : Load"%rv)

# get slot list
rv = p11_lib.C_GetSlotList(0, slotList) 
print("%s : C_GetSlotList"%rv)

# start a session
session = LowLevel.CK_SESSION_HANDLE()
rv = p11_lib.C_OpenSession(slotList[0], LowLevel.CKF_SERIAL_SESSION | LowLevel.CKF_RW_SESSION, session)
print("%s : C_OpenSession"%rv)

# login
rv = p11_lib.C_Login(session, LowLevel.CKU_USER, pin)
print("%s : C_Login"%rv)

# get data from a file
# with open(filepath, 'r') as file:
    # data = LowLevel.ckbytelist(bytearray(file.read(), encoding='utf8'))
data = LowLevel.ckbytelist(bytearray('a'*2, encoding='utf8'))
# search key by name
search_result = LowLevel.ckobjlist(1)
search_template = LowLevel.ckattrlist(1)
search_template[0].SetString(LowLevel.CKA_LABEL, key_name)

rv = p11_lib.C_FindObjectsInit(session, search_template)
print('%s : C_FindObjectsInit'%rv)

rv = p11_lib.C_FindObjects(session, search_result)
print('%s : C_FindObjects'%rv)

rv = p11_lib.C_FindObjectsFinal(session)
print('%s : C_FindObjectsFinal'%rv)

if search_result:
    print("Key found.")

    # assign mechanism
    signature = LowLevel.ckbytelist()
    mechanism = LowLevel.CK_MECHANISM()
    mechanism.mechanism = hash_mechanism

    # start signing
    # rv = p11_lib.C_SignInit(session, mechanism, search_result[0])
    # print('%s : C_SignInit'%rv)

    # rv = p11_lib.C_Sign(session, data, signature)
    # print('%s : C_Sign 1'%rv)

    # rv = p11_lib.C_Sign(session, data, signature)
    # print('%s : C_Sign 2'%rv)

    # sig = bytes(signature).hex()
    sig = 'abcdef'
    print('Sign:', sig)

    # # Begin verify
    rv = p11_lib.C_VerifyInit(session, mechanism, search_result[0])
    print('%s : C_VerifyInit'%rv)
    rv = p11_lib.C_Verify(session, data, signature)
    print('%s : C_Verify'%rv)

    if rv == LowLevel.CKR_OK:
        print('Verify True')
    else:
        print('Verify False')
else:
    print('Key not found')

# logout
rv = p11_lib.C_Logout (session)
print("%s : C_Logout"%rv)

# close session
rv = p11_lib.C_CloseSession(session)
print("%s : C_CloseSession"%rv)