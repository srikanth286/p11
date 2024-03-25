# This program encrypts and decrypts data using an asymmetric key
from PyKCS11 import LowLevel
import argparse

description = '''
Perform an encrypt and decrypt with an asymmetric key
Example:
./pkcs11_encrypt_decrypt_asymm_key.py -p hunter2 -k key_name -f /path/to/file.txt'''
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

# get data from a file
with open(filepath, 'r') as file:
    data = LowLevel.ckbytelist(bytes(file.read(), 'utf-8'))

# search key by name
priv_object = LowLevel.ckobjlist(1)
search_template_priv = LowLevel.ckattrlist(2)
search_template_priv[0].SetString(LowLevel.CKA_LABEL, key_name)
search_template_priv[1].SetNum(LowLevel.CKA_CLASS, LowLevel.CKO_PRIVATE_KEY)

rv = p11_lib.C_FindObjectsInit(session, search_template_priv)
print('%s : C_FindObjectsInit'%rv)
rv = p11_lib.C_FindObjects(session, priv_object)
print('%s : C_FindObjects'%rv)
rv = p11_lib.C_FindObjectsFinal(session)
print('%s : C_FindObjectsFinal'%rv)

pub_object = LowLevel.ckobjlist(1)
search_template_pub = LowLevel.ckattrlist(2)
search_template_pub[0].SetString(LowLevel.CKA_LABEL, key_name)
search_template_pub[1].SetNum(LowLevel.CKA_CLASS, LowLevel.CKO_PUBLIC_KEY)

rv = p11_lib.C_FindObjectsInit(session, search_template_pub) 
print('%s : C_FindObjectsInit'%rv)
rv = p11_lib.C_FindObjects(session, pub_object)
print('%s : C_FindObjects'%rv)
rv = p11_lib.C_FindObjectsFinal(session)
print('%s : C_FindObjectsFinal'%rv)

if priv_object and pub_object:
    print("Key found.")

    # assign mechanism
    encrypted_data = LowLevel.ckbytelist()
    decrypted_data = LowLevel.ckbytelist()
    mechanism = LowLevel.CK_MECHANISM()   
    mechanism.mechanism = LowLevel.CKM_RSA_PKCS

    # start encryption with public key
    rv = p11_lib.C_EncryptInit (session, mechanism, pub_object[0])
    print('%s : C_EncryptInit'%rv)
    
    rv = p11_lib.C_Encrypt(session, data, encrypted_data)
    print('%s : C_Encrypt 1'%rv)
    rv = p11_lib.C_Encrypt(session, data, encrypted_data)
    print('%s : C_Encrypt 2'%rv)

    enc = bytes(encrypted_data).hex()
    print('Encrypted data:', enc)

    # Begin decryption with private key
    rv = p11_lib.C_DecryptInit(session, mechanism, priv_object[0])
    print('%s : C_DecryptInit'%rv)
    rv = p11_lib.C_Decrypt(session, encrypted_data, decrypted_data)
    print('%s : C_Decrypt 1'%rv)
    rv = p11_lib.C_Decrypt(session, encrypted_data, decrypted_data)
    print('%s : C_Decrypt 2'%rv)

    if rv != LowLevel.CKR_OK:
        print('C_Decrypt failed!')
    else:
        plain_text = ''.join(chr(i) for i in data)
        decrypted_text = ''.join(chr(i) for i in decrypted_data)
        print("text :", plain_text)
        print("decrypted text :", decrypted_text)
else:
    print('Key not found')

# logout
rv = p11_lib.C_Logout (session)
print("%s : C_Logout"%rv)

# close session
rv = p11_lib.C_CloseSession(session)
print("%s : C_CloseSession"%rv)