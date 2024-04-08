# This program create an asymmetric EC key
from PyKCS11 import LowLevel
import argparse
from asn1crypto.keys import ECDomainParameters, NamedCurve

def searchKey(p11Lib, session, key_name, cko_object):
    search_result = LowLevel.ckobjlist(1)
    search_template = LowLevel.ckattrlist(2)
    search_template[0].SetString(LowLevel.CKA_LABEL, key_name)
    search_template[1].SetNum(LowLevel.CKA_CLASS, cko_object)

    rv = p11Lib.C_FindObjectsInit(session, search_template)
    print('%s : C_FindObjectsInit'%rv)

    rv = p11Lib.C_FindObjects(session, search_result)
    print('%s : C_FindObjects'%rv)

    rv = p11Lib.C_FindObjectsFinal(session)
    print('%s : C_FindObjectsFinal'%rv)

    return search_result

def createKeyPair (session, keyname, p11Lib):
    curve = u"secp256r1"

    # Setup the domain parameters, unicode conversion needed for the curve string
    domain_params = ECDomainParameters(name="named", value=NamedCurve(curve))
    ec_params = domain_params.dump()
    
    pub_object = LowLevel.CK_OBJECT_HANDLE()
    priv_object = LowLevel.CK_OBJECT_HANDLE()
    pub_template = LowLevel.ckattrlist(7)
    priv_template = LowLevel.ckattrlist(9)
    mechanism = LowLevel.CK_MECHANISM()
    mechanism.mechanism = LowLevel.CKM_ECDSA_KEY_PAIR_GEN

    # Create the Public Key Template
    pub_template[0].SetString(LowLevel.CKA_LABEL, keyname)
    pub_template[1].SetNum(LowLevel.CKA_CLASS, LowLevel.CKO_PUBLIC_KEY)
    pub_template[2].SetBool(LowLevel.CKA_TOKEN, True)
    pub_template[4].SetBool(LowLevel.CKA_ENCRYPT, True)
    pub_template[3].SetBool(LowLevel.CKA_VERIFY, True)
    pub_template[4].SetBool(LowLevel.CKA_WRAP, True)
    pub_template[5].SetNum(LowLevel.CKA_KEY_TYPE, LowLevel.CKK_ECDSA)
    pub_template[6].SetBin(LowLevel.CKA_EC_PARAMS, ec_params)
    
    # Create the Private Key Template
    priv_template[0].SetString(LowLevel.CKA_LABEL, keyname)
    priv_template[1].SetNum(LowLevel.CKA_CLASS, LowLevel.CKO_PRIVATE_KEY)
    priv_template[2].SetNum(LowLevel.CKA_KEY_TYPE, LowLevel.CKK_ECDSA)
    priv_template[3].SetBool(LowLevel.CKA_TOKEN, True)
    priv_template[4].SetBool(LowLevel.CKA_PRIVATE, True)
    priv_template[5].SetBool(LowLevel.CKA_SENSITIVE, True)
    priv_template[6].SetBool(LowLevel.CKA_DECRYPT, True)
    priv_template[7].SetBool(LowLevel.CKA_SIGN, True)
    priv_template[8].SetBool(LowLevel.CKA_UNWRAP, True)

    rv = p11Lib.C_GenerateKeyPair(session, mechanism,  pub_template, priv_template, pub_object, priv_object)
    print('%s : C_GenerateKeyPair'%rv)

description = '''
Create an ecdsa key 
Example:
python3 pkcs11_create_asym_ec_key.py -p hunter2 -k key_name'''
parser = argparse.ArgumentParser(description = description , \
    formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-p', help='pin', required=True, dest='pin')
parser.add_argument('-k', help='key name', required=True, dest='key_name')

args = parser.parse_args()
pin = bytes(args.pin, 'utf-8')
key_name = args.key_name

# creates a CPKCS11Lib instance
p11Lib = LowLevel.CPKCS11Lib() 
lib_path = '/lib/softhsm/libsofthsm2.so'

# creates a ckintlist instance to store the slot_list
slot_list = LowLevel.ckintlist() 
rv = p11Lib.Load(lib_path)
print("%s : Load"%rv)

# get slot list
rv = p11Lib.C_GetSlotList(0, slot_list) 
print("%s : C_GetSlotList"%rv)

# start a session
session = LowLevel.CK_SESSION_HANDLE()
rv = p11Lib.C_OpenSession(slot_list[0], LowLevel.CKF_SERIAL_SESSION | LowLevel.CKF_RW_SESSION, session)
print("%s : C_OpenSession"%rv)

# login
rv = p11Lib.C_Login(session, LowLevel.CKU_USER, pin)
print("%s : C_Login"%rv)

#First try to find the key, if the key doesn't exist, create it.   
search_result_pub = searchKey(p11Lib, session, key_name, LowLevel.CKO_PUBLIC_KEY)
search_result_priv = searchKey(p11Lib, session, key_name, LowLevel.CKO_PRIVATE_KEY) 

if search_result_priv:
    print("Key found. Not creating one.")
else:
    createKeyPair (session, key_name, p11Lib)

# logout
rv = p11Lib.C_Logout (session)
print("%s : C_Logout"%rv)

# close session
rv = p11Lib.C_CloseSession(session)
print("%s : C_CloseSession"%rv)

