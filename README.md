# softhsm

## running
docker build -t softhsm:2.5.0 .
docker run -it --name softhsm --rm softhsm:2.5.0 bash
docker run -d --name softhsm softhsm:2.5.0 

# testing

# python code

# references

https://github.com/psmiraglia/docker-softhsm/blob/master/README.md

path:
/usr/local/lib/softhsm/libsofthsm2.so

# show version
softhsm2-util -v

# init token
softhsm2-util --init-token --slot 0 --label "test_token" --so-pin test123 --pin qwerty123

# show slots
softhsm2-util --show-slots

# delete slot
softhsm2-util --delete-token --serial 13deefedf026de1b


# python stuff
docker build -t p11 .
docker run -it --name p11 --rm p11 sh

# run simple alpine image
docker run -it --name noo --rm alpine:3.8 sh

## pkcs11
x pkcs11_random.py
python3 pkcs11_random.py -p qwerty123 -n 10

x pkcs11_digest.py
python3 pkcs11_digest.py -p qwerty123 -f pkcs11_consts.py -m sha256

x pkcs11_find_all.py
python3 pkcs11_find_all.py -p qwerty123

### symm key
x pkcs11_create_symm_key.py
python3 pkcs11_create_symm_key.py -p qwerty123 -n 256 -k key1

x pkcs11_destroy_symm_key.py
python3 pkcs11_destroy_symm_key.py -p qwerty123 -k key1

? pkcs11_sign_verify_symm_key_obj.py
python3 pkcs11_sign_verify_symm_key_obj.py -p qwerty123 -k key2 -f pkcs11_consts.py -m sha1

x pkcs11_encrypt_decrypt_symm_key.py
python3 pkcs11_encrypt_decrypt_symm_key.py -p qwerty123 -f /tmp/abc.txt -m cbc_pad -k key1

- pkcs11_import_symm_key.py
- pkcs11_export_raw_symm_key.py
- pkcs11_wrap_symm_key.py
- pkcs11_unwrap_symm_key.py

### asymm key rsa
- pkcs11_create_asymm_rsa_key.py
- pkcs11_destroy_asymm_key_rsa.py
- pkcs11_sign_verify_asymm.py
- pkcs11_encrypt_decrypt_asymm_key.py
- pkcs11_import_asymm_key.py
- pkcs11_export_asymm_key.py


- pkcs11_get_attribute.py

- pkcs11_add_custom_attribute.py
- pkcs11_migrate_symm_key.py
- pkcs11_symm_headers_encrypt_decrypt.py



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