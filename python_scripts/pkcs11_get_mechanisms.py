# This program create a symmetric key
from PyKCS11 import LowLevel
import argparse
from pkcs11_consts import ckm

description = '''
Get a list of all the mechanisms
Example:
python3 pkcs11_get_mechanisms.py -p hunter2'''
parser = argparse.ArgumentParser(description = description , \
    formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-p', help='pin', required=True, dest='pin')

args = parser.parse_args()
pin = bytes(args.pin, 'utf-8')

p11_lib = LowLevel.CPKCS11Lib() 
lib_path = '/lib/softhsm/libsofthsm2.so'

# creates a ckulonglist instance to store the SlotList 
slotList = LowLevel.ckulonglist() 
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

mech_bin_list = LowLevel.ckintlist(200)
rv = p11_lib.C_GetMechanismList(slotList[0], mech_bin_list)
print("%s : C_GetMechanismList"%rv)
print(len(mech_bin_list), 'mechanisms allowed:')
for m in mech_bin_list:
    if m in ckm:
        print(ckm[m])

# logout
rv = p11_lib.C_Logout (session)
print("%s : C_Logout"%rv)

# close session
rv = p11_lib.C_CloseSession(session)
print("%s : C_CloseSession"%rv)