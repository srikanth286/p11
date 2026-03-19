# softhsm
This repo contains a set of pkcs11 python examples that can be used to 
- Generate random bytes
- Create symmetric, asymmetric keys
- Sign, verify with symmetric and asymmetric keys
- Encrypt and decrypt with symmetric and asymmetric keys

## Running the container the easy way
```sh
# build and run
make build

# just run
make run

# stop and bring down the container
make down

# stop the containers and remove volumes
make wipe
```

## The path to the softhsm lib
```sh
/usr/local/lib/softhsm/libsofthsm2.so
```

## softhsm commands
```sh
# show version
softhsm2-util -v

# init token
softhsm2-util --init-token --slot 0 --label "test_token" --so-pin test123 --pin qwerty123

# show slots
softhsm2-util --show-slots

# delete slot
softhsm2-util --delete-token --serial 13deefedf026de1b
```

## pkcs11
```sh
# get into the container
cd p11

#--- Random ---#
python3 pkcs11_random.py -p qwerty123 -n 10

#--- Digest ---#
python3 pkcs11_digest.py -p qwerty123 -f pkcs11_consts.py -m sha256

#--- symm key ---#
# create
python3 pkcs11_create_sym_key.py -p qwerty123 -n 256 -k key1

#--- find keys ---#
python3 pkcs11_find_all.py -p qwerty123

#--- get attributes ---#
python3 pkcs11_get_attribute.py -p qwerty123 -k key1 -a CKA_UNWRAP

#--- destroy ---#
python3 pkcs11_destroy_sym_key.py -p qwerty123 -k key1

#--- create generic secret key ---#
python3 pkcs11_create_generic_secret_key.py -p qwerty123 -n 256 -k gen_sec

#--- sign, verify ---#
python3 pkcs11_sign_verify_sym_key.py -p qwerty123 -f /tmp/abc.txt -m sha256 -k gen_sec

# encrypt, decrypt
python3 pkcs11_encrypt_decrypt_sym_key.py -p qwerty123 -f /tmp/abc.txt -m cbc_pad -k key1

x pkcs11_import_sym_key.py  >> not possible cka_value is readonly
x pkcs11_export_raw_sym_key.py >> not possible
- pkcs11_wrap_sym_key.py
- pkcs11_unwrap_sym_key.py

### asymm key rsa
x pkcs11_create_asym_rsa_key.py
python3 pkcs11_create_asym_rsa_key.py -p qwerty123 -n 2048 -k rsa2k

x pkcs11_sign_verify_asym_rsa_key.py
python3 pkcs11_sign_verify_asym_rsa_key.py -p qwerty123 -f /tmp/abc.txt -k rsa2k

x pkcs11_encrypt_decrypt_asym_rsa_key.py
python3 pkcs11_encrypt_decrypt_asym_rsa_key.py -p qwerty123 -k rsa2k -f /tmp/abc.txt 

x pkcs11_destroy_asym_rsa_key.py
python3 pkcs11_destroy_asym_rsa_key.py -p qwerty123 -k rsa2k

- pkcs11_import_asymm_key.py
- pkcs11_export_asymm_key.py

### asymm key EC
x pkcs11_create_asym_ec_key.py
python3 pkcs11_create_asym_ec_key.py -p qwerty123 -k ec1

x pkcs11_sign_verify_asym_ec.py
python3 pkcs11_sign_verify_asym_ec_key.py -p qwerty123 -k ec1 -f /tmp/abc.txt

x pkcs11_destroy_asym_ec_key.py
python3 pkcs11_destroy_asym_ec_key.py -p qwerty123 -k ec1

- pkcs11_import_asymm_key_ec.py
- pkcs11_export_asymm_key_ec.py
```

# get syslog running
rsyslogd

https://www.keyfactor.com/blog/what-is-acme-protocol-and-how-does-it-work/

# opensc
apt install opensc-pkcs11
opensc-tool -h
pkcs11-tool --module /lib/softhsm/libsofthsm2.so -l -t

## Docker helper commands
```sh
# build the container
docker build -t softhsm:2.5.0 .

# run the container in interactive mode
docker run -it --name softhsm --rm softhsm:2.5.0 bash

# run the container in detached mode
docker run -d --name softhsm softhsm:2.5.0 

# python stuff
docker build -t p11 .
docker run -it --name p11 --rm p11 sh

# run simple alpine image
docker run -it --name noo --rm alpine:3.8 sh
```

# notes
python3 pkcs11_find_all.py -p qwerty123
python3 pkcs11_create_symm_key.py -p qwerty123 -n 128 -k asd1
python3 pkcs11_sign_verify_symm_key_obj.py -p qwerty123 -f pkcs11_consts.py -m sha256 -k key5

# list slots, enter pin, test
pkcs11-tool --module /lib/softhsm/libsofthsm2.so -l -p qwerty123 -t
# get all mechanism
pkcs11-tool --module /lib/softhsm/libsofthsm2.so -l -M -p qwerty123 -t

# using opensc
- create a symmetric key
pkcs11-tool --module /lib/softhsm/libsofthsm2.so -p qwerty123 --keygen --key-type aes:32 -a key4
- get all the attributes and respective values
- try to sign 
- run with pykcs11

  label:      key5
  Usage:      encrypt, decrypt, verify, wrap, unwrap
  Access:     sensitive, always sensitive, never extractable, local


## references
https://github.com/psmiraglia/docker-softhsm/blob/master/README.md