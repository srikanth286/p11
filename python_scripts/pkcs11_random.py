# This program gets n random bytes
from PyKCS11 import LowLevel
import argparse

description = '''
Get n random bytes
Example:
./pkcs11_random.py -p hunter2 -n 10'''
parser = argparse.ArgumentParser(description = description , \
    formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-p', help='pin', required=True, dest='pin')
parser.add_argument('-n', help='number of bytes', required=True, dest='n_bytes', type=int)

args = parser.parse_args()
pin = bytes(args.pin, 'utf-8')
number_of_bytes = args.n_bytes

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

random_bytes = LowLevel.ckbytelist(number_of_bytes)

# generate random bytes
rv = p11_lib.C_GenerateRandom(session, random_bytes)
print('%s : C_GenerateRandom'%rv)

hex_rand = bytes(random_bytes).hex()
print('random : %s'%hex_rand)

# logout
rv = p11_lib.C_Logout (session)
print("%s : C_Logout"%rv)

# close session
rv = p11_lib.C_CloseSession(session)
print("%s : C_CloseSession"%rv)