# This program destroys an asymmetric ec key
from PyKCS11 import LowLevel
import argparse

description = '''
Destroy an asymmetric ec key
Example:
python3 pkcs11_destroy_asym_ec_key.py -p hunter2 -k asymmetric_key_name'''
parser = argparse.ArgumentParser(description = description , \
    formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-p', help='pin', required=True, dest='pin')
parser.add_argument('-k', help='key name', required=True, dest='key_name')

args = parser.parse_args()
pin = bytes(args.pin, 'utf-8')
key_name = args.key_name

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
rv = p11_lib.C_OpenSession(slot_list[0], LowLevel.CKF_SERIAL_SESSION | LowLevel.CKF_RW_SESSION, session)
print("%s : C_OpenSession"%rv)

# login
rv = p11_lib.C_Login(session, LowLevel.CKU_USER, pin)
print("%s : C_Login"%rv)

# search key by name
search_result = LowLevel.ckobjlist(2)
search_template = LowLevel.ckattrlist(1)
search_template[0].SetString(LowLevel.CKA_LABEL, key_name)

rv = p11_lib.C_FindObjectsInit(session, search_template)
print('%s : C_FindObjectsInit'%rv)

rv = p11_lib.C_FindObjects(session, search_result)
print('%s : C_FindObjects'%rv)

rv = p11_lib.C_FindObjectsFinal(session)
print('%s : C_FindObjectsFinal'%rv)

if search_result:
    print('Key found. ')
    # destroy the keypair object
    for keypair in search_result:
        rv = p11_lib.C_DestroyObject (session, keypair)
        print('%s : C_DestroyObject'%rv)
else:
    print('Key not found.')

# logout
rv = p11_lib.C_Logout (session)
print("%s : C_Logout"%rv)

# close session
rv = p11_lib.C_CloseSession(session)
print("%s : C_CloseSession"%rv)
