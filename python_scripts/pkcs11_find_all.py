# This program finds all the objects in the hsm
from PyKCS11 import LowLevel
import argparse
import pkcs11_consts as const

description = '''
Find all the objects in the HSM
Example:
./pkcs11_find_all.py -p hunter2 '''
parser = argparse.ArgumentParser(description = description , formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-p', help='pin', required=True, dest='pin')

args = parser.parse_args()
pin = bytes(args.pin, 'utf-8')

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
search_result = LowLevel.ckobjlist(100)
search_template = LowLevel.ckattrlist(1)
search_template[0].SetBool(LowLevel.CKA_TOKEN, True)

rv = p11_lib.C_FindObjectsInit(session, search_template)
print('%s : C_FindObjectsInit'%rv)

rv = p11_lib.C_FindObjects(session, search_result)
print('%s : C_FindObjects'%rv)

rv = p11_lib.C_FindObjectsFinal(session)
print('%s : C_FindObjectsFinal'%rv)

if search_result:
    print('Total number of keys:', len(search_result))
    
    for res_handle in search_result:
        obj_template = LowLevel.ckattrlist(3)
        obj_template[0].SetType(LowLevel.CKA_LABEL)
        obj_template[1].SetType(LowLevel.CKA_KEY_TYPE)
        obj_template[2].SetType(LowLevel.CKA_VALUE_LEN)

        rv = p11_lib.C_GetAttributeValue(session, res_handle, obj_template)
        print('%s : C_GetAttributeValue'%rv)
        rv = p11_lib.C_GetAttributeValue(session, res_handle, obj_template)
        print('%s : C_GetAttributeValue'%rv)
        
        print('Key handle :', res_handle.value())
        for i, o in enumerate(obj_template):
            if i == 0:
                print('key name is:',o.GetString())
            if i == 1:
                t =  o.GetNum()
                print('Key type is:', const.ckk[t])
            if i == 2:
                print('Key size is:', o.GetNum(), 'bytes')
        print('-'*10)
else:
    print('No objects in the HSM.')

# logout
rv = p11_lib.C_Logout (session)
print("%s : C_Logout"%rv)

# close session
rv = p11_lib.C_CloseSession(session)
print("%s : C_CloseSession"%rv)
