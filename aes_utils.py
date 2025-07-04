from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

# Key must be 16, 24, or 32 bytes long
def get_key(password):
    return hashlib.sha256(password.encode()).digest()

def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    return text[:-ord(text[-1])]

def encrypt_vote(vote, password):
    key = get_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_vote = pad(vote)
    encrypted = cipher.encrypt(padded_vote.encode('utf-8'))
    return base64.b64encode(iv + encrypted).decode('utf-8')

def decrypt_vote(encrypted_vote, password):
    key = get_key(password)
    raw = base64.b64decode(encrypted_vote)
    iv = raw[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(raw[16:]).decode('utf-8')
    return unpad(decrypted)
