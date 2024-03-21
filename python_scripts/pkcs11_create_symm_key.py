# This program create a symmetric key
from PyKCS11 import LowLevel
import argparse

description = '''
Create a symmetric key (versioned/non versioned)
The key can also be rotated with the -r switch
Example:
./pkcs11_create_symm_key.py -p hunter2 -k aes_key_name -n 256'''
parser = argparse.ArgumentParser(description = description , \
    formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-p', help='pin', required=True, dest='pin')
parser.add_argument('-k', help='key name', required=True, dest='key_name')
parser.add_argument('-n', help='key size (128|256)', required=True, dest='size', type=int)

args = parser.parse_args()
pin = bytes(args.pin, 'utf-8')
key_name = args.key_name
size = int(args.size/8)

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
    print('Key found. Not creating it.')
else:
    obj_template = LowLevel.ckattrlist(12)
    mechanism = LowLevel.CK_MECHANISM()
    mechanism.mechanism = LowLevel.CKM_AES_KEY_GEN
    handle_obj = LowLevel.CK_OBJECT_HANDLE()
    
    # Create the Key Template 
    obj_template[0].SetBool(LowLevel.CKA_TOKEN, True)
    obj_template[1].SetNum(LowLevel.CKA_CLASS, LowLevel.CKO_SECRET_KEY)
    obj_template[2].SetNum(LowLevel.CKA_KEY_TYPE, LowLevel.CKK_AES)
    obj_template[3].SetString(LowLevel.CKA_LABEL, key_name)    
    obj_template[4].SetNum(LowLevel.CKA_VALUE_LEN, size) # 32 for AES256 and 16 for AES128
    obj_template[5].SetBool(LowLevel.CKA_ENCRYPT, True)
    obj_template[6].SetBool(LowLevel.CKA_DECRYPT, True)
    obj_template[7].SetBool(LowLevel.CKA_SIGN, True)
    obj_template[8].SetBool(LowLevel.CKA_VERIFY, True)
    obj_template[9].SetBool(LowLevel.CKA_WRAP, True)
    obj_template[10].SetBool(LowLevel.CKA_UNWRAP, True)
    obj_template[11].SetBool(LowLevel.CKA_SENSITIVE, True)
    # obj_template[12].SetBool(LowLevel.CKA_ALWAYS_SENSITIVE, True)
    # obj_template[12].SetBool(LowLevel.CKA_NEVER_EXTRACTABLE, True)
    # obj_template[12].SetBool(LowLevel.CKA_LOCAL, True)
    # obj_template[12].SetBool(LowLevel.CKA_EXTRACTABLE, True)

    rv = p11_lib.C_GenerateKey (session, mechanism,  obj_template, handle_obj)
    print('%s : C_GenerateKey'%rv)

# logout
rv = p11_lib.C_Logout (session)
print("%s : C_Logout"%rv)

# close session
rv = p11_lib.C_CloseSession(session)
print("%s : C_CloseSession"%rv)
