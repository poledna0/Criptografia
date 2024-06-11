from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import pickle
import hashlib

def encrypt(plain_text, key):
    if isinstance(plain_text, str):
        plain_text = bytes(plain_text, 'utf-8')

    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the key
    private_key = hashlib.scrypt(key.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(plain_text)
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }


def decrypt(enc_dict, key):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])

    # generate the private key from the key and salt
    private_key = hashlib.scrypt(key.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted

def salvar_encriptado(objeto: object, caminho: str) -> None:
    with open(caminho, 'wb') as f:
        f.write(pickle.dumps(objeto))

def carregar_encriptado(caminho: str) -> object:
    with open(caminho, 'rb') as f:
        return pickle.loads(f.read())

def carrega_imagem(caminho: str) -> bytes:
    with open(caminho, 'rb') as f:
        return f.read()

def salvar_imagem(b: bytes, caminho: str) -> None:
    with open(caminho, 'wb') as f:
        f.write(b)

def main():
    chave = input("chave: ")
    imagem = carrega_imagem('pou_oliginal.jpg')
    imagem_cript = encrypt(imagem,chave)
    salvar_encriptado(imagem_cript,'popo')
    img = carregar_encriptado('popo')
    v = decrypt(img, chave)
    salvar_imagem(v,'popo.jpg')

    # Carregue a imagem original usando a função carrega_imagem
    # Encripte a imagem original usando a função encrypt
    # Salve a imagem encriptada usando salvar_encriptado
    # Carregue a imagem encriptada usando a função carregar_encriptado
    # Decripte a imagem encriptada usando a função decrypt
    # Salve a imagem decriptada usando a função salvar_imagem

main()