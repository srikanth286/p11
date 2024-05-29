# softhsm

## Running the softhsm container
```sh
docker build -t softhsm:2.5.0 .
docker run -it --name softhsm --rm softhsm:2.5.0 bash
docker run -d --name softhsm softhsm:2.5.0 
```

## references
https://github.com/psmiraglia/docker-softhsm/blob/master/README.md

## path to the lib:
/usr/local/lib/softhsm/libsofthsm2.so

## show version
softhsm2-util -v

## init token
softhsm2-util --init-token --slot 0 --label "test_token" --so-pin test123 --pin qwerty123

## show slots
softhsm2-util --show-slots

## delete slot
softhsm2-util --delete-token --serial 13deefedf026de1b


# Building and running
docker build -t p11 .
docker run -it --name p11 --rm p11 sh

# run simple alpine image
docker run -it --name noo --rm alpine:3.8 sh

## pkcs11 examples
```python
pkcs11_random.py
python3 pkcs11_random.py -p qwerty123 -n 10

pkcs11_digest.py
python3 pkcs11_digest.py -p qwerty123 -f pkcs11_consts.py -m sha256

pkcs11_find_all.py
python3 pkcs11_find_all.py -p qwerty123

pkcs11_get_attribute.py
python3 pkcs11_get_attribute.py -p qwerty123 -k rsa1 -a CKA_UNWRAP

### symm key
pkcs11_create_symm_key.py
python3 pkcs11_create_sym_key.py -p qwerty123 -n 256 -k key1

pkcs11_destroy_symm_key.py
python3 pkcs11_destroy_sym_key.py -p qwerty123 -k key1

pkcs11_encrypt_decrypt_symm_key.py
python3 pkcs11_encrypt_decrypt_sym_key.py -p qwerty123 -f /tmp/abc.txt -m cbc_pad -k key1

Todos:
- pkcs11_import_sym_key.py
- pkcs11_export_raw_sym_key.py
- pkcs11_wrap_sym_key.py
- pkcs11_unwrap_sym_key.py

### asymm key rsa
pkcs11_create_asym_rsa_key.py
python3 pkcs11_create_asym_rsa_key.py -p qwerty123 -n 2048 -k rsa1

pkcs11_destroy_asym_rsa_key.py
python3 pkcs11_destroy_asym_rsa_key.py -p qwerty123 -k rsa2k

pkcs11_sign_verify_asym_rsa_key.py
python3 pkcs11_sign_verify_asym_rsa_key.py -p qwerty123 -f /tmp/abc.txt -k rsa2k

pkcs11_encrypt_decrypt_asym_rsa_key.py
python3 pkcs11_encrypt_decrypt_asym_rsa_key.py -p qwerty123 -k rsa2k -f /tmp/abc.txt 

Todos:
- pkcs11_import_asymm_key.py
- pkcs11_export_asymm_key.py

### asymm key EC
pkcs11_create_asym_ec_key.py
python3 pkcs11_create_asym_ec_key.py -p qwerty123 -k ec1

pkcs11_destroy_asym_ec_key.py
python3 pkcs11_destroy_asym_ec_key.py -p qwerty123 -k ec1

pkcs11_sign_verify_asym_ec.py
python3 pkcs11_sign_verify_asym_ec_key.py -p qwerty123 -k ec1 -f /tmp/abc.txt

Todos:
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
