# This program gets a particular attribute value for a key / object
from PyKCS11 import LowLevel
import argparse
from pkcs11_consts import cka

def get_attribute(atr_name):
    if cka.get(atr_name)!=None:
        return cka[atr_name]
    else:
        print('Incorrect attribute :', atr_name)
        exit()

description = '''
Get an attribute value for a key / object
Example:
python3 pkcs11_get_attribute.py -p hunter2 -k aes_key_name -a CKA_WRAP'''
parser = argparse.ArgumentParser(description = description , \
    formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-p', help='pin', required=True, dest='pin')
parser.add_argument('-k', help='key name', required=True, dest='key_name')
parser.add_argument('-a', help='key attribute', dest='atr')

args = parser.parse_args()
pin = bytes(args.pin, 'utf-8')
key_name = args.key_name
attribute = args.atr
attribute_value = get_attribute(attribute)

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
    print('Key found.')
    obj_template = LowLevel.ckattrlist(1)
    obj_template[0].SetType(attribute_value)
    rv = p11_lib.C_GetAttributeValue(session, search_result[0], obj_template)
    print('%s : C_GetAttributeValue'%rv)

    rv = p11_lib.C_GetAttributeValue(session, search_result[0], obj_template)
    print('%s : C_GetAttributeValue'%rv)

    for o in obj_template:
        if o.IsBin():
            print('Attribute value is:',o.GetBin())
        if o.IsBool():
            print('Attribute value is:',o.GetBool())
        if o.IsNum():
            print('Attribute value is:',o.GetNum())
        if o.IsString():
            print('Attribute value is:',o.GetString())
else:
    print('Key does not exist.')

# logout
rv = p11_lib.C_Logout (session)
print("%s : C_Logout"%rv)

# close session
rv = p11_lib.C_CloseSession(session)
print("%s : C_CloseSession"%rv)