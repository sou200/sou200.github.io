---
title: "Cyber Odessy CTF 2025 Cryptography Official Writeups"
date: 2025-12-05 12:00:00 +0800
categories: [cryptography]
tags: [cryptography]
---

# Cyber Odessy CTF 2025 Cryptography Official Writeups

## [Sistim Taye7](https://github.com/Akasec-1337/Cyber-Odyssey-2025-Finals/tree/main/Cryptography/Sistim%20Taye7)
**Don't ask me If you find an error in the challenge,
because even me I can't fix it.**

**Code:**
```py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import ast
import os
import base64
import datetime

flag = open("flag.txt", "r").read().strip()
key = os.urandom(16)

next_user_id = 1
current_id = 0

ALG_AES_CBC = 1
ALG_AES_GCM = 2

users = {}


def encrypt_GCM(data, iv):
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()
    return encryptor.update(data) + encryptor.finalize(), encryptor.tag


def decrypt_GCM(data, iv, tag):
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).decryptor()
    return decryptor.update(data) + decryptor.finalize_with_tag(tag)


def encrypt_CBC(data, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_CBC(data, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def encrypt_cheque(cheque):
    cheque = str(cheque).encode()
    alg = users[current_id]["alg"]
    token = None
    if alg == ALG_AES_CBC:
        iv = os.urandom(16)
        enc_cheque = encrypt_CBC(cheque, iv)
        token = {"enc_cheque": enc_cheque.hex(), "iv": iv.hex()}
    elif alg == ALG_AES_GCM:
        iv = os.urandom(12)
        enc_cheque, tag = encrypt_GCM(cheque, iv)
        token = {"enc_cheque": enc_cheque.hex(), "iv": iv.hex(), "tag": tag.hex()}
    token["alg"] = alg
    return base64.b64encode(str(token).encode()).decode()


def decrypt_cheque(token):
    token = base64.b64decode(token).decode()
    token = ast.literal_eval(token)
    if not isinstance(token, dict):
        print("bad cheque")
        return None
    alg = token["alg"]
    iv = bytes.fromhex(token["iv"])
    enc_cheque = bytes.fromhex(token["enc_cheque"])
    cheque = None
    if alg == ALG_AES_CBC:
        cheque = decrypt_CBC(enc_cheque, iv)
    elif alg == ALG_AES_GCM:
        tag = bytes.fromhex(token["tag"])
        cheque = decrypt_GCM(enc_cheque, iv, tag)
    else:
        return None
    cheque = ast.literal_eval(cheque.decode())
    return cheque


def add_account(username, password, balance):
    global next_user_id

    users[next_user_id] = {
        "username": username,
        "password": password,
        "balance": balance,
        "alg": ALG_AES_CBC,
    }
    next_user_id += 1


def login():
    global next_user_id, current_id
    username = str(input("username: "))
    password = str(input("password: "))
    for user_id in users:
        if (
            users[user_id]["username"] == username
            and users[user_id]["password"] == password
        ):
            current_id = user_id
            print(f"Welcome {users[current_id]['username']}!")
            return
    print("Invalid Credentials.")


def register(balance=0):
    username = input("username: ")
    password = input("password: ")

    if (
        len(username) < 3
        or len(username) > 20
        or not username.isalnum()
        or len(password) < 3
        or len(password) > 20
        or not password.isprintable()
    ):
        print("Invalid input.")
        return
    add_account(username, password, balance)


def make_cheque():
    if users[current_id]["balance"] >= 1000:
        print(
            f"this is your golden cheque Mr/Mrs. {users[current_id]['username']}: {flag}"
        )
    amount = int(input("amount: "))
    receiver_id = int(input("receiver id: "))

    timestamp = int(datetime.datetime.now().timestamp())
    cheque_token = {
        "timestamp": timestamp,
        "receiver_id": receiver_id,
        "amount": amount,
    }
    print(f"Cheque token: {encrypt_cheque(cheque_token)}")


def validate_cheque(cheque):
    sender_id, receiver_id = cheque["sendr_id"], cheque["receiver_id"]
    amount = cheque["amount"]

    sender = users[sender_id]
    if (
        (sender_id == receiver_id)
        or sender_id not in users
        or receiver_id != current_id
        or amount < 1
        or sender["balance"] < amount
    ):
        return None, None, True
    return sender_id, amount, False


def cash_cheque():
    token = str(input("Cheque token: "))
    cheque = decrypt_cheque(token)

    sender_id, amount, error = validate_cheque(cheque)
    if error:
        print("Invalid cheque!")
        return
    sender = users[sender_id]
    sender["balance"] = sender["balance"] - amount
    users[current_id]["balance"] += amount
    print("Cashing cheque successfully")


def logout():
    global current_id
    current_id = 0


def update_enc_alg():
    print(
        f"current alg is {'AES-CBC' if users[current_id]['alg'] == ALG_AES_CBC else 'AES-GCM'}"
    )
    print("1 -> AES-CBC\n2 -> AES-GCM")
    alg_num = int(input("> "))
    if alg_num not in {ALG_AES_CBC, ALG_AES_GCM}:
        print("invalid input")
        return
    users[current_id]["alg"] = alg_num


def print_user_info():
    global current_id
    print(
        f"Hi {users[current_id]['username']}, your balance is {users[current_id]['balance']}\nYour Account ID: {current_id}"
    )


def print_options_1():
    print(
        """1- Login
2- Register
3- Exit"""
    )


def print_options_2():
    print(
        """1- Make a cheque
2- Cash a cheque
3- update encryption spec
4- Logout
5- Exit"""
    )


BANNER_MAIN = """
╔══════════════════════════════════════════════╗
║          🏦BANKA CHARIKA LMOBARIKA🏦         ║
╠══════════════════════════════════════════════╣
║            Trusted Since 2024                ║
║     Your Security is Our Priority            ║
╚══════════════════════════════════════════════╝"""

if __name__ == "__main__":
    add_account("akhnouch", flag, 1337)
    print(BANNER_MAIN)
    while True:
        if current_id in users:
            print_user_info()
            print_options_2()
            option = int(input("> "))
            if option == 1:
                make_cheque()
            elif option == 2:
                cash_cheque()
            elif option == 3:
                update_enc_alg()
            elif option == 4:
                logout()
            elif option == 5:
                exit()
        else:
            print_options_1()
            option = int(input("> "))
            if option == 1:
                login()
            elif option == 2:
                register()
            elif option == 3:
                exit()

```

**Solve:**
the challenge is just a simple AES CBC bit flipping in the IV. then you can change the sender id and send the amount you want.

**Code:**
```py
from pwn import *
import ast
import base64

io = process(["python3", "chall.py"])


def register(user, password):
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"username: ")
    io.sendline(user)
    io.recvuntil(b"password: ")
    io.sendline(password)


def login(user, password):
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"username: ")
    io.sendline(user)
    io.recvuntil(b"password: ")
    io.sendline(password)


def logout():
    io.recvuntil(b"> ")
    io.sendline(b"4")


def update_alg(alg):
    io.recvuntil(b"> ")
    io.sendline(b"3")
    io.recvuntil(b"> ")
    io.sendline(alg)


def cash_cheque(token):
    token = base64.b64encode(token)
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"Cheque token: ")
    io.sendline(token)


def print_flag():
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"user: ")
    print(io.recvline()[:-1].decode())


def make_cheque(amount, to):
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"amount: ")
    io.sendline(amount)
    io.recvuntil(b"receiver id: ")
    io.sendline(to)
    io.recvuntil(b"Cheque token: ")
    token = io.recvline()[:-1]
    token = base64.b64decode(token).decode()
    token = ast.literal_eval(token)
    return token


register(b"user", b"pass")
login(b"user", b"pass")
token = make_cheque(b"1000", b"2")

iv = bytearray.fromhex(token["iv"])
original_block = b"{'timestamp': 17"
maded_block = b"{'sendr_id':1,0:"

iv = xor(iv, xor(original_block, maded_block))
token["iv"] = iv.hex()
token = str(token).encode()

cash_cheque(token)
print_flag()

```

## [DON'TTAKEITPERSONALLY](https://github.com/Akasec-1337/Cyber-Odyssey-2025-Finals/tree/main/Cryptography/DON'TTAKEITPERSONALLY)
**“if you want to shine like sun first you have to burn like it.”
― Adolf Hitler**

**Code:**
```py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import ast
import os
import base64
import datetime

flag = open("flag.txt", "r").read().strip()
key = os.urandom(16)

next_user_id = 1
current_id = 0

ALG_AES_CBC = 1
ALG_AES_GCM = 2
CHEQUE_EXPIRING_EN_SEC = 30

users = {}


def encrypt_GCM(data, iv):
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()
    return encryptor.update(data) + encryptor.finalize(), encryptor.tag


def decrypt_GCM(data, iv, tag):
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).decryptor()
    return decryptor.update(data) + decryptor.finalize_with_tag(tag)


def encrypt_CBC(data, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_CBC(data, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def encrypt_cheque(cheque):
    cheque = str(cheque).encode()
    alg = users[current_id]["alg"]
    token = None
    if alg == ALG_AES_CBC:
        iv = os.urandom(16)
        enc_cheque = encrypt_CBC(cheque, iv)
        token = {"enc_cheque": enc_cheque.hex(), "iv": iv.hex()}
    elif alg == ALG_AES_GCM:
        iv = os.urandom(12)
        enc_cheque, tag = encrypt_GCM(cheque, iv)
        token = {"enc_cheque": enc_cheque.hex(), "iv": iv.hex(), "tag": tag.hex()}
    token["alg"] = alg
    return base64.b64encode(str(token).encode()).decode()


def decrypt_cheque(token):
    token = base64.b64decode(token).decode()
    token = ast.literal_eval(token)
    if not isinstance(token, dict):
        print("bad cheque")
        return None
    alg = token["alg"]
    iv = bytes.fromhex(token["iv"])
    enc_cheque = bytes.fromhex(token["enc_cheque"])
    cheque = None
    if alg == ALG_AES_CBC:
        cheque = decrypt_CBC(enc_cheque, iv)
    elif alg == ALG_AES_GCM:
        tag = bytes.fromhex(token["tag"])
        cheque = decrypt_GCM(enc_cheque, iv, tag)
    else:
        return None
    cheque = ast.literal_eval(cheque.decode())
    return cheque


def add_account(username, password, balance):
    global next_user_id

    users[next_user_id] = {
        "username": username,
        "password": password,
        "balance": balance,
        "alg": ALG_AES_CBC,
    }
    next_user_id += 1


def login():
    global next_user_id, current_id
    username = str(input("username: "))
    password = str(input("password: "))
    for user_id in users:
        if (
            users[user_id]["username"] == username
            and users[user_id]["password"] == password
        ):
            current_id = user_id
            print(f"Welcome {users[current_id]['username']}!")
            return
    print("Invalid Credentials.")


def register(balance=0):
    username = input("username: ")
    password = input("password: ")

    if (
        len(username) < 3
        or len(username) > 20
        or not username.isalnum()
        or len(password) < 3
        or len(password) > 20
        or not password.isprintable()
    ):
        print("Invalid input.")
        return
    add_account(username, password, balance)


def make_cheque():
    if users[current_id]["balance"] >= 1000:
        print(
            f"this is your golden cheque Mr/Mrs. {users[current_id]['username']}: {flag}"
        )
    amount = int(input("amount: "))
    receiver_id = int(input("receiver id: "))
    timestamp = int(datetime.datetime.now().timestamp())
    cheque_token = {
        "timestamp": timestamp,
        "sender_id": current_id,
        "receiver_id": receiver_id,
        "amount": amount,
    }
    print(f"Cheque token: {encrypt_cheque(cheque_token)}")


def validate_cheque(cheque):
    sender_id, receiver_id = cheque["sender_id"], cheque["receiver_id"]
    amount = cheque["amount"]

    timestamp = cheque["timestamp"]
    current_timestamp = int(datetime.datetime.now().timestamp())

    sender = users[sender_id]
    if (
        (sender_id == receiver_id)
        or sender_id not in users
        or receiver_id != current_id
        or amount < 1
        or sender["balance"] < amount
        or current_timestamp - timestamp > CHEQUE_EXPIRING_EN_SEC
    ):
        return None, None, True
    return sender_id, amount, False


def cash_cheque():
    token = str(input("Cheque token: "))
    cheque = decrypt_cheque(token)
    if not isinstance(cheque, dict):
        return print("invalid cheque")

    sender_id, amount, error = validate_cheque(cheque)
    if error:
        return print("Invalid cheque!")
    sender = users[sender_id]
    sender["balance"] = sender["balance"] - amount
    users[current_id]["balance"] += amount
    print("Cashing cheque successfully")


def logout():
    global current_id
    current_id = 0


def update_enc_alg():
    print(
        f"current alg is {'AES-CBC' if users[current_id]['alg'] == ALG_AES_CBC else 'AES-GCM'}"
    )
    print("1 -> AES-CBC\n2 -> AES-GCM")
    alg_num = int(input("> "))
    if alg_num not in {ALG_AES_CBC, ALG_AES_GCM}:
        print("invalid input")
        return
    users[current_id]["alg"] = alg_num


def print_user_info():
    global current_id
    print(
        f"Hi {users[current_id]['username']}, your balance is {users[current_id]['balance']}\nYour Account ID: {current_id}"
    )


BANNER = r"""
 ________  ___      ___ ________     _____     
|\   __  \|\  \    /  /|\   ___  \  / __  \    
\ \  \|\  \ \  \  /  / | \  \\ \  \|\/_|\  \   
 \ \  \\\  \ \  \/  / / \ \  \\ \  \|/ \ \  \  
  \ \  \\\  \ \    / /   \ \  \\ \  \   \ \  \ 
   \ \_______\ \__/ /     \ \__\\ \__\   \ \__\
    \|_______|\|__|/       \|__| \|__|    \|__|
"""


def print_options_1():
    print(
        """1- Login
2- Register
3- Exit"""
    )


def print_options_2():
    print(
        """1- Make a cheque
2- Cash a cheque
3- update encryption spec
4- Logout
5- Exit"""
    )


if __name__ == "__main__":
    print(BANNER)
    add_account("siraj_dine", flag, 1337)
    while True:
        try:
            if current_id in users:
                print_user_info()
                print_options_2()
                option = int(input("> "))
                if option == 1:
                    make_cheque()
                elif option == 2:
                    cash_cheque()
                elif option == 3:
                    update_enc_alg()
                elif option == 4:
                    logout()
                elif option == 5:
                    exit()
            else:
                print_options_1()
                option = int(input("> "))
                if option == 1:
                    login()
                elif option == 2:
                    register()
                elif option == 3:
                    exit()
        except Exception as e:
            print(f"Error: {e}")
```

**Solve:**
The challenge is just bypassing the auth tag by exploiting cryptography python package.
```A flaw was found in python-cryptography versions between >=1.9.0 and <2.3. The finalize_with_tag API did not enforce a minimum tag length. If a user did not validate the input length prior to passing it to finalize_with_tag an attacker could craft an invalid payload with a shortened tag (e.g. 1 byte) such that they would have a 1 in 256 chance of passing the MAC check. GCM tag forgeries can cause key leakage.```

**Code:**
```py
from pwn import *
import ast
import base64

io = process(["python3", "chall.py"])


def register(user, password):
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"username: ")
    io.sendline(user)
    io.recvuntil(b"password: ")
    io.sendline(password)


def login(user, password):
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"username: ")
    io.sendline(user)
    io.recvuntil(b"password: ")
    io.sendline(password)


def logout():
    io.recvuntil(b"> ")
    io.sendline(b"4")


def update_alg(alg):
    io.recvuntil(b"> ")
    io.sendline(b"3")
    io.recvuntil(b"> ")
    io.sendline(alg)


def cash_cheque(token):
    token = base64.b64encode(token)
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"Cheque token: ")
    io.sendline(token)


def print_flag():
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"user: ")
    print(io.recvline()[:-1].decode())


def make_cheque(amount, to):
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"amount: ")
    io.sendline(amount)
    io.recvuntil(b"receiver id: ")
    io.sendline(to)
    io.recvuntil(b"Cheque token: ")
    token = io.recvline()[:-1]
    token = base64.b64decode(token).decode()
    token = ast.literal_eval(token)
    return token


register(b"user", b"pass")
login(b"user", b"pass")
update_alg(b"2")

token = make_cheque(b"1000", b"2")

enc_cheque = bytearray.fromhex(token["enc_cheque"])
enc_cheque[39] = enc_cheque[39] ^ ord("2") ^ ord("1")
token["enc_cheque"] = enc_cheque.hex()

for byte in range(256):
    token["tag"] = f"{byte:02x}"
    payload = str(token).encode()
    cash_cheque(payload)
    res = io.recvuntil(b"1- ")
    if b"successfully" in res:
        print_flag()
        break
```

## [sourceless](https://github.com/Akasec-1337/Cyber-Odyssey-2025-Finals/tree/main/Cryptography/sourceless)
**maybe it looks familiar but it's not, maybe it looks guessy but it's not.
maybe and maybe bla bla bla ... just solve it.**

**ciphertext**
```
8b1eec5cbc226bd03631fa3b5c725157d1a9b2b85dce41c3c1fccd0c04d39f21a0cbde80a6071e2b32096c2e0eff33d844ee6d675407ace18289357d60ba4b2daa4ed4d070fec06687e249e0e6f9ee45861c4f67e887dec85292d36ab05cd7a1a727522853a0acfad59379b3e050338bf9f23cfc172ee7872346ad27d7568ba9896f1b7da6b5991251debdf2c2b7df6201fdd3362399091f0a29550df3505b6a
```

**Solve:**
this is just a SHA1 hash of 8 parts of the flag use any hash cracker
https://crackstation.net/ (Recommended)
![solve](https://github.com/Akasec-1337/Cyber-Odyssey-2025-Finals/blob/main/Cryptography/sourceless/solve.png?raw=true)

## [True Story](https://github.com/Akasec-1337/Cyber-Odyssey-2025-Finals/tree/main/Cryptography/True%20Story)
**Ibrahim started out glowing with excitement in Khouribga’s 1337, friends, and the sweet freedom of student life.
From the calm vibes of Khenifra, he felt like he finally found his place, debugging happily and laughing his way through sleepless nights.
Then he moved to Tangier and suddenly the guy who once smiled at compiler errors now gets depressed by the wind, the noise, and even the Wi-Fi.**

**Code:**
```py
from binascii import unhexlify
from Crypto.Cipher import AES
import random
from Crypto.Random import get_random_bytes

flag = open("flag.txt", "r").read().strip().encode()
key = get_random_bytes(32)
print(key[:8])


def xor(a, b):
    data = []
    for x, y in zip(a, b):
        data.append(x ^ y)
    return bytes(data)


class CTR:
    def __init__(self):
        self.key = key

    def encrypt(self, data):
        nonce = get_random_bytes(8)
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(data)
        return ciphertext, nonce

    def decrypt(self, ciphertext, nonce):
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(ciphertext)


class feedfront:
    def __init__(self, size):
        self.size = size
        self.state = random.getrandbits(size)

    def next_state(self):
        self.state = (self.state >> 1) | (
            (
                (
                    (self.state >> 13)
                    ^ (self.state >> 37)
                    ^ (self.state >> random.randint(1, self.size - 1))
                )
                & 1
            )
            << (self.size - 1)
        )

    def noise(self, n):
        zeros = random.randint(0, n - 1)
        noise = [0] * zeros + [1] * (n - zeros)
        random.shuffle(noise)
        return noise

    def get_byte(self):
        b_data = 0
        while b_data == 0:
            for _ in range(8):
                lsb = self.state & 1
                b_data = (b_data << 1) | lsb
                self.next_state()
        return b_data

    def get_rand_bytes(self, size):
        data = []
        for _ in range(size):
            data.append(self.get_byte())
        return bytes(data)

    def encrypt(self, data):
        key = self.get_rand_bytes(len(data))
        return xor(data, key)


BANNER = r"""
      ___           ___           ___     
     /\  \         /\  \         /\  \    
    /::\  \        \:\  \       /::\  \   
   /:/\:\  \        \:\  \     /:/\:\  \  
  /:/  \:\  \       /::\  \   /::\~\:\  \ 
 /:/__/ \:\__\     /:/\:\__\ /:/\:\ \:\__\
 \:\  \ /:/  /    /:/  \/__/ \/__\:\/:/  /
  \:\  /:/  /    /:/  /           \::/  / 
   \:\/:/  /     \/__/             \/__/  
    \::/  /                               
     \/__/                                
"""

if __name__ == "__main__":
    print(BANNER)
    enc1 = feedfront(64)
    enc2 = CTR()
    while True:
        print(
            """1 - Encrypt data
2 - Encrypt flag
3 - Exit"""
        )
        opt = int(input(">> "))
        if opt == 1:
            data = unhexlify(input("data: "))
            c1 = enc1.encrypt(data)
            print(f"c1 = {c1.hex()}")
            c2, nonce = enc2.encrypt(data)
            print(f"c2 = {nonce.hex()}:{c2.hex()}")
            c3 = xor(c1, c2)
            print(f"c3 = {c3.hex()}")
        elif opt == 2:
            c1 = enc1.encrypt(flag)
            print(f"c1 = {c1.hex()}")
            c2, nonce = enc2.encrypt(flag)
            print(f"c2 = {nonce.hex()}:{c2.hex()}")
            c3 = xor(c1, c2)
            print(f"c3 = {c3.hex()}")
        else:
            exit()
```

**Solve:**
as you can see the first algorithm that I used is LSFR and the bytes that are generated cannot contain a NULL bytes as this code tells:
```py
def get_byte(self):
    b_data = 0
    while b_data == 0:
        for _ in range(8):
            lsb = self.state & 1
            b_data = (b_data << 1) | lsb
            self.next_state()
    return b_data
```
so `b_data` is always non NULL (`\x00`).
**The vulnerability:** 
if I have `x = b'A'` and I did encrypt `x` it will never be `'A'` again because the LSFR always non NULL so the XOR will never return the same value. so the algorithm will return every value, but not the encrypted value.

**Solve Code:**
```py
from pwn import process
from string import printable

io = process(["python3", "chall.py"])

flag_len = 0

prob = {}


def clear_dict(data):
    for i, c in enumerate(data):
        if chr(c) in prob[i]:
            prob[i].remove(chr(c))


def init_dict(data):
    l = len(data)
    for i in range(l):
        prob[i] = list(printable)


def print_prob():
    data = ""
    for l in prob.values():
        data += l[0]
    print(data)
    if "AKASEC" in data:
        exit()


for i in range(2000000):
    io.recvuntil(b">> ")
    io.sendline(b"2")
    io.recvuntil(b"c1 = ")
    out = bytes.fromhex(io.recvline()[:-1].decode())
    if i == 0:
        init_dict(out)
    clear_dict(out)
    print_prob()
    print(i)
```