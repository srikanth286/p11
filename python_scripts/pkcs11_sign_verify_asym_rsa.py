# This program performs a sign and a verify with an asymmetric key
from PyKCS11 import LowLevel
import argparse

description = '''
Perform a sign and verify using an asymmetric key
Example:
python3 pkcs11_sign_verify_asym_rsa.py -p hunter2 -k key_name -f /path/to/file.txt'''
parser = argparse.ArgumentParser(description = description , \
    formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-p', help='pin', required=True, dest='pin')
parser.add_argument('-k', help='key name', required=True, dest='key_name')
parser.add_argument('-f', help='file path', required=True, dest='filepath')

args = parser.parse_args()
pin = bytes(args.pin, 'utf-8')
key_name = args.key_name
filepath = args.filepath

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
with open(filepath, 'r') as file:
    data = LowLevel.ckbytelist(bytes(file.read(), 'utf-8'))

# search the key by name
search_result_priv = LowLevel.ckobjlist(1)
search_template_priv = LowLevel.ckattrlist(2)
search_template_priv[0].SetString(LowLevel.CKA_LABEL, key_name)
search_template_priv[1].SetNum(LowLevel.CKA_CLASS, LowLevel.CKO_PRIVATE_KEY)

search_result_pub = LowLevel.ckobjlist(1)
search_template_pub = LowLevel.ckattrlist(2)
search_template_pub[0].SetString(LowLevel.CKA_LABEL, key_name)
search_template_pub[1].SetNum(LowLevel.CKA_CLASS, LowLevel.CKO_PUBLIC_KEY)

rv = p11_lib.C_FindObjectsInit(session, search_template_priv)
print('%s : C_FindObjectsInit'%rv)
rv = p11_lib.C_FindObjects(session, search_result_priv)
print('%s : C_FindObjects'%rv)
rv = p11_lib.C_FindObjectsFinal(session)
print('%s : C_FindObjectsFinal'%rv)

rv = p11_lib.C_FindObjectsInit(session, search_template_pub)
print('%s : C_FindObjectsInit'%rv)
rv = p11_lib.C_FindObjects(session, search_result_pub)
print('%s : C_FindObjects'%rv)
rv = p11_lib.C_FindObjectsFinal(session)
print('%s : C_FindObjectsFinal'%rv)

if search_result_priv and search_result_pub:
    print("Key found.")

    # assign mechanism
    signature = LowLevel.ckbytelist()
    mechanism = LowLevel.CK_MECHANISM()
    mechanism.mechanism = LowLevel.CKM_RSA_PKCS 

    # start signing
    rv = p11_lib.C_SignInit(session, mechanism, search_result_priv[0])
    print('%s : C_SignInit'%rv)

    rv = p11_lib.C_Sign(session, data, signature)
    print('%s : C_Sign 1'%rv)

    rv = p11_lib.C_Sign(session, data, signature)
    print('%s : C_Sign 2'%rv)

    sig = bytes(signature).hex()
    print('Sign:', sig)

    # Begin verify
    rv = p11_lib.C_VerifyInit(session, mechanism, search_result_pub[0])
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