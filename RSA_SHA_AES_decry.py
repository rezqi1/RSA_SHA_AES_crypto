from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from RSA_SHA_AES_enc import rsa_priv,aes_key
import hashlib

def dechiffer_fichier( file_ch,file_dech, aes_key,rsa_private_key):
    with open(file_ch,"rb") as f:
        data=f.read()

    iv=data[:16]
    aes_key_crypted=data[16:16+256]
    content_crypted=data[16+256:]


    cipher_rsa=PKCS1_OAEP.new(rsa_private_key)
    aes_key=cipher_rsa.decrypt(aes_key_crypted)



    cipher_aes=AES.new(aes_key,AES.MODE_CBC,iv)
    content_decrypted=unpad(cipher_aes.decrypt(content_crypted),AES.block_size)


    with open(file_dech,"wb") as f:
        f.write(content_decrypted)

    
    print(f"File '{file_ch}'saved under '{file_dech}'")


def hasher(file_name='file_decrypted.txt'):
    hasher=hashlib.sha256()
    with open(file_name,"rb") as f:
        while bloc := f.read(4096):
            hasher.update(bloc)
    print('file hashed')
    return hasher.hexdigest() # return as hexadecimal value

hashed_value=hasher()
print(hashed_value)
def check_the_hash():
    with open("hashed_value.txt","r") as f:
        hashed_val=f.read()
    print(hashed_val)
    if hashed_val==hashed_value:
        print('---------the value is correct--------------')
    else:
        print("---------------there is a problem!!!------------")
    




def verify_file_decrypted(name_file_decypted):
    with open(name_file_decypted,"r") as f:
        content=f.read()
    print('content decrypted',content)

check_the_hash()
dechiffer_fichier('file_crypted_hash.aes','file_decrypted.txt',aes_key,rsa_priv)
verify_file_decrypted('file_decrypted.txt')
