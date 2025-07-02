from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
import hashlib

def generate_key_rsa():
    key_pair=RSA.generate(2048)
    public_key=key_pair.public_key()
    private_key=key_pair
    print('RSA key generated')
    return public_key,private_key


def generated_key_and_iv():
    key=get_random_bytes(16)
    iv=get_random_bytes(16)
    print("key and iv generated")
    return key,iv

def create_file(myFile, content):
    with open(myFile, "wb") as f:
        f.write(content.encode())  # Convert string to bytes before writing
    print(f"File '{myFile}' created.")


def chiffer_fichier(file_c, file_ch, aes_key, iv,rsa_public_key):
    with open(file_c,"rb") as f:
        content=f.read()

    cipher_aes=AES.new(aes_key,AES.MODE_CBC,iv)
    content_crypted=cipher_aes.encrypt(pad(content,AES.block_size))


    cipher_rsa=PKCS1_OAEP.new(rsa_public_key)
    aes_key_crypted=cipher_rsa.encrypt(aes_key)


    with open(file_ch,"wb") as f:
        f.write(iv + aes_key_crypted + content_crypted)

    print(f"File '{file_c}'saved under '{file_ch}'")
    

def hasher(file_name="fclair_hash.txt"):
    hasher=hashlib.sha256()
    with open(file_name,"rb") as f:
        while bloc := f.read(4096):
            hasher.update(bloc)
    print('file hashed')
    return hasher.hexdigest() # return as hexadecimal value
    
rsa_pub,rsa_priv = generate_key_rsa()
aes_key,iv = generated_key_and_iv()
create_file("fclair_hash.txt","hello world")
chiffer_fichier("fclair_hash.txt",'file_crypted_hash.aes',aes_key,iv,rsa_pub)

hashed_value=hasher()

def create_file_hashed_value(myFile, content):
    with open(myFile, "wb") as f:
        f.write(content.encode())  # Convert string to bytes before writing
    print(f"File '{myFile}' created.")

create_file_hashed_value("hashed_value.txt",hashed_value)