#!/usr/bin/env python3.11
import random
import subprocess
import shlex
import time
import platform

crypto = 0

def clear_screen():
    """Clear the screen based on the operating system."""
    os_name = platform.system()
    if os_name == "Linux" or os_name == "Darwin":
        subprocess.run(["clear"])
    elif os_name == "Windows":
        subprocess.run(["cls"], shell=True)
    else:
        print("\n" * 100)  # A simple workaround for unsupported OS

def ready():
    banner = """
__________                 ___ ___               __   
|______   \__ __  ____    /   |   \ __ __  _____/  |_ 
 |    |  _/  |  \/ ___\  /    ~    \  |  \/    \   __|
 |    |   \  |  / /_/  > \    Y    /  |  /   |  \  |  
 |______  /____/\___  /   \___|_  /|____/|___|  /__|  
        \/     /_____/          \/            \/      

"""
    print(banner)
    introduction = """\
In this game, you're a computer hacker participating in a digital heist.
In order to get the crypto, you need to identify vulnerabilities in the
code. The harder the level, the more you earn.
(Type "exit" to quit)
(DISCLAIMER: This is not a crypto game)
"""
    print(introduction)
    print(f"Current crypto: {crypto} BTC")
    level = "Pick a level:\n 1. Easy\n 2. Medium\n 3. Hard\n-> "
    difficulty = input(level)

    if difficulty == "1":
        clear_screen()
        easy_difficulty()
    elif difficulty == "2":
        clear_screen()
        medium_difficulty()
    elif difficulty == "3":
        clear_screen()
        hard_difficulty()
    elif difficulty.lower() == "exit":
        clear_screen()
        print("Exiting game in 5 seconds, thanks for playing...")
        time.sleep(5)
        exit()
    else:
        clear_screen()
        print("Invalid input. Please try again.")
        ready()

def easy_difficulty():
    global crypto

    questions = {
        "sql_injection": """user_input = input("Enter your username: ")
query = f"SELECT * FROM users WHERE username = '{user_input}';""",
        "xss": """<div>Welcome, <?php echo $_GET['username']; ?></div>""",
        "file_inclusion": """$file = $_GET['file'];
include($file);""",
        "command_injection": """$url = $_GET['url'];
system($url);""",
        "insecure_deserialization": """import pickle
data = pickle.loads(request.data)""",
        "open_redirect": """from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/login')
def login():
    next_url = request.args.get('next')
    # Login logic here...
    return redirect(next_url)

# Assume login logic goes here
""",
        "hardcoded_api_key": """api_key = "12345-ABCDE-67890"
response = requests.get(f"https://api.example.com/data?key={api_key}")""",
        "directory_transversal": """\
file_path = "/var/www/html/" + input("Enter the file name: ")
with open(file_path, 'r') as file:
    data = file.read()
""",

        
    }

    options = ["SQL Injection", "XSS", "File Inclusion", "Command Injection", "Insecure Deserialization", "Hardcoded API Key", "Open Redirect", "Directory Transversal"]
    questions = {k.lower(): v for k, v in questions.items()}
    option_mapping = {k: str(i + 1) for i, k in enumerate(questions.keys())}

    print("Easy difficulty selected...")
    score = 0

    for i in range(5):
        correct_key, question = random.choice(list(questions.items()))
        correct_answer = option_mapping[correct_key]
        print(f"\nSnippet {i + 1}:\n{question}")
        print("\nOptions: 1. SQL Injection, 2. XSS, 3. File Inclusion, 4. Command Injection, 5. Insecure Deserialization, 6. Open Redirect, 7. Hardcoded API Key 8. Directory Transversal")
        answer = input("Your answer (1-8): ").strip()
        
        if answer == correct_answer:
            clear_screen()
            print("Correct!")
            questions.pop(correct_key)
            score += 1
        else:
            clear_screen()
            print(f"Incorrect. The correct answer is: {correct_answer}")
        print(f"Score: {score}/5")

    if score == 5:
        print("Congratulations! You have completed the easy difficulty level.")
        crypto += 10

    else:
        print("You have failed the easy difficulty level. Please try again.")

    ready()

def medium_difficulty():
    global crypto
    questions = {
        "csrf": """<form action="/transfer" method="POST">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="to_account" value="123456">
</form>""",
        "file upload": '''move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $_FILES['file']['name']);''',
        "hardcoded credentials": '''$username = "admin"; $password = "admin";''',
        "xxe": """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><tag>&xxe;</tag>""",
        "weak cryptography": """from Crypto.Cipher import DES
cipher = DES.new('8bytekey', DES.MODE_ECB)""",
        "ssrf": """import requests
from flask import Flask, request, send_file
from io import BytesIO

app = Flask(__name__)

@app.route('/thumbnail')
def thumbnail():
    image_url = request.args.get('url')
    image_response = requests.get(image_url)
    
    # Assume some image processing happens here
    img_io = BytesIO(image_response.content)
    img_io.seek(0)
    return send_file(img_io, mimetype='image/jpeg')
""",
        "path_transversal": """from flask import Flask, send_from_directory, request

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_from_directory('/secure_directory', filename)
""",
        "insecure_jwt_implementation": """\
import jwt
token = jwt.encode({"user": "admin"}, "secret", algorithm="HS256")
""",
    }

    options = ["csrf", "file upload", "hardcoded credentials", "xxe", "weak cryptography", "ssrf", "insecure jwt implementation"]
    questions = {k.lower(): v for k, v in questions.items()}
    option_mapping = {k: str(i + 1) for i, k in enumerate(questions.keys())}

    print("Medium difficulty selected...")
    score = 0

    for i in range(5):
        correct_key, question = random.choice(list(questions.items()))
        correct_answer = option_mapping[correct_key]
        print(f"\nSnippet {i + 1}:\n{question}")
        print("Options: 1. csrf, 2. file upload, 3. hardcoded credentials, 4. xxe, 5. weak cryptography, 6. ssrf, 7. path transversal, 8. insecure jwt implementation")
        answer = input("Your answer (1-8): ").strip()

        if answer == correct_answer:
            clear_screen()
            print("Correct!")
            questions.pop(correct_key)
            score += 1
        else:
            clear_screen()
            print(f"Incorrect. The correct answer is: {correct_answer}")
        print(f"Score: {score}/5")

    if score == 5:
        clear_screen()
        print("Congratulations! You have completed the medium difficulty level.")
        crypto += 20

    else:
        clear_screen()
        print("You have failed the medium difficulty level. Please try again.")

    ready()

def hard_difficulty():
    global crypto
    questions = {
        "buffer overflow": """void vulnerable_function(char *user_input) {
    char buffer[10];
    strcpy(buffer, user_input);
}""",
        "race condition": """def transfer(from_account, to_account, amount):
    balance = get_balance(from_account)
    if balance >= amount:
        set_balance(from_account, balance - amount)
        set_balance(to_account, get_balance(to_account) + amount)""",
        "improper input validation": """int validate_user(int user_id) {
    if (user_id > 0) {
        return 1;
    }
    return 0;
}""",
        "clickjacking": """<iframe src="http://vulnerable-site.com" style="opacity:0;"></iframe>""",
        "ldap injection": """query = f"(&(uid={user_input})(objectClass=person))""",
        "padding_oracle_attack": """from flask import Flask, request
from Crypto.Cipher import AES
import base64

app = Flask(__name__)

key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_CBC, iv=b'RandomIV12345678')

@app.route('/decrypt')
def decrypt():
    encrypted_data = base64.b64decode(request.args.get('data'))
    try:
        plaintext = cipher.decrypt(encrypted_data)
        # Check for padding and handle errors here
        return f'Decrypted data: {plaintext}'
    except ValueError:
        return 'Decryption failed due to padding error', 400
""",
        "use_after_free": """#include <stdio.h>
#include <stdlib.h>

int main() {
    int *ptr = malloc(sizeof(int));
    *ptr = 5;
    free(ptr);
    printf("%d\n", *ptr);
    return 0;
}
""",
        "integer_overflow": """\
int add(int a, int b) {
    return a + b;
}
int main() {
    int x = 2147483647;
    int y = 1;
    printf("%d\n", add(x, y));
}
""",
    }

    options = ["buffer overflow", "race condition", "improper input validation", "clickjacking", "ldap injection", "padding oracle attack", "user after free", "integer overflow"]
    questions = {k.lower(): v for k, v in questions.items()}
    option_mapping = {k: str(i + 1) for i, k in enumerate(questions.keys())}

    score = 0

    for i in range(5):
        correct_key, question = random.choice(list(questions.items()))
        correct_answer = option_mapping[correct_key]
        print(f"\nSnippet {i + 1}:\n{question}")
        print("Options: 1. buffer overflow, 2. race condition, 3. improper input validation, 4. clickjacking, 5. ldap injection, 6. padding oracle attack, 7. use after free, 8. integer overflow")
        answer = input("Your answer (1-8): ").strip()

        if answer == correct_answer:
            clear_screen()
            print("Correct!")
            questions.pop(correct_key)
            score += 1
        else:
            clear_screen()
            print(f"Incorrect. The correct answer is: {correct_answer}")
        
        print(f"Score: {score}/5")

    if score == 5:
        clear_screen()
        print("Congratulations! You have completed the hard difficulty level.")
        crypto += 40

    else:
        clear_screen()
        print("You have failed the hard difficulty level. Please try again.")

    ready()

if __name__ == "__main__":
    ready()

