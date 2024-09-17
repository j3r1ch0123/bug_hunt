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

def ask_questions(questions, options):
    """Handles the asking of questions and returns the score."""
    score = 0
    total_questions = 5

    for i in range(total_questions):
        # Pick a random question that hasn't been used yet
        correct_key, question_data = random.choice(list(questions.items()))
        correct_answer = question_data["correct"]
        question_text = question_data["question"]
        
        # Display question and options
        print(f"\nSnippet {i + 1}:\n{question_text}")
        print("Options: " + ', '.join([f"{idx}. {opt}" for idx, opt in enumerate(options, 1)]))
        
        # Get user answer
        answer = input("Your answer (1-8): ").strip()

        if answer == correct_answer:
            clear_screen()
            print("Correct!")
            score += 1
        else:
            clear_screen()
            print(f"Incorrect. The correct answer was: {correct_answer}")
        
        print(f"Score: {score}/{total_questions}")

        # Remove the question that was just asked
        del questions[correct_key]

    return score

def easy_difficulty():
    global crypto

    questions = {
        "sql_injection": {
            "question": """user_input = input("Enter your username: ")
query = f"SELECT * FROM users WHERE username = '{user_input}';""",
            "correct": "1"
        },
        "xss": {
            "question": """<div>Welcome, <?php echo $_GET['username']; ?></div>""",
            "correct": "2"
        },
        "file_inclusion": {
            "question": """$file = $_GET['file'];
include($file);""",
            "correct": "3"
        },
        "command_injection": {
            "question": """$url = $_GET['url'];
system($url);""",
            "correct": "4"
        },
        "insecure_deserialization": {
            "question": """import pickle
data = pickle.loads(request.data)""",
            "correct": "5"
        },
        "open_redirect": {
            "question": """from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/login')
def login():
    next_url = request.args.get('next')
    # Login logic here...
    return redirect(next_url)""",
            "correct": "6"
        },
        "hardcoded_api_key": {
            "question": """api_key = "12345-ABCDE-67890"
response = requests.get(f"https://api.example.com/data?key={api_key}")""",
            "correct": "7"
        },
        "directory_transversal": {
            "question": """\
file_path = "/var/www/html/" + input("Enter the file name: ")
with open(file_path, 'r') as file:
    data = file.read()
""",
            "correct": "8"
        },
    }

    options = [
        "SQL Injection", "XSS", "File Inclusion", "Command Injection", 
        "Insecure Deserialization", "Open Redirect", "Hardcoded API Key", 
        "Directory Transversal"
    ]

    print("Easy difficulty selected...")
    score = ask_questions(questions, options)

    if score == 5:
        print("Congratulations! You have completed the easy difficulty level.")
        crypto += 10
    else:
        print("You have failed the easy difficulty level. Please try again.")

    ready()

def medium_difficulty():
    global crypto

    questions = {
        "csrf": {
            "question": """<form action="/transfer" method="POST">
<input type="hidden" name="amount" value="1000">
<input type="hidden" name="to_account" value="123456">
</form>""",
            "correct": "1"
        },
        "file_upload": {
            "question": '''move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $_FILES['file']['name']);''',
            "correct": "2"
        },
        "hardcoded_credentials": {
            "question": '''$username = "admin"; $password = "admin";''',
            "correct": "3"
        },
        "xxe": {
            "question": """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><tag>&xxe;</tag>""",
            "correct": "4"
        },
        "weak_cryptography": {
            "question": """from Crypto.Cipher import DES
cipher = DES.new('8bytekey', DES.MODE_ECB)""",
            "correct": "5"
        },
        "ssrf": {
            "question": """import requests
from flask import Flask, request, send_file
from io import BytesIO

app = Flask(__name__)

@app.route('/thumbnail')
def thumbnail():
    image_url = request.args.get('url')
    image_response = requests.get(image_url)
    
    img_io = BytesIO(image_response.content)
    img_io.seek(0)
    return send_file(img_io, mimetype='image/jpeg')""",
            "correct": "6"
        },
        "path_transversal": {
            "question": """from flask import Flask, send_from_directory, request

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_from_directory('/secure_directory', filename)""",
            "correct": "7"
        },
        "insecure_jwt_implementation": {
            "question": """import jwt
token = jwt.encode({"user": "admin"}, "secret", algorithm="HS256")""",
            "correct": "8"
        }
    }

    options = [
        "CSRF", "File Upload", "Hardcoded Credentials", "XXE", "Weak Cryptography",
        "SSRF", "Path Transversal", "Insecure JWT Implementation"
    ]

    print("Medium difficulty selected...")
    score = ask_questions(questions, options)

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
        "buffer_overflow": {
            "question": """void vulnerable_function(char *user_input) {
char buffer[10];
strcpy(buffer, user_input);
}""",
            "correct": "1"
        },
        "race_condition": {
            "question": """def transfer(from_account, to_account, amount):
balance = get_balance(from_account)
if balance >= amount:
    set_balance(from_account, balance - amount)
    set_balance(to_account, get_balance(to_account) + amount)""",
            "correct": "2"
        },
        "improper_input_validation": {
            "question": """int validate_user(int user_id) {
if (user_id > 0) {
    return 1;
}
return 0;
}""",
            "correct": "3"
        },
        "clickjacking": {
            "question": """<iframe src="http://example.com/login" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>""",
            "correct": "4"
        },
        "side_channel_attack": {
            "question": """def check_password(password):
secret_password = "mysecretpassword"
for i in range(len(password)):
    if password[i] != secret_password[i]:
        return False
return True""",
            "correct": "5"
        },
        "broken_authentication": {
            "question": """if password == "password123":
login(user)""",
            "correct": "6"
        },
        "code_injection": {
            "question": """exec(input("Enter your Python code: "))""",
            "correct": "7"
        },
        "reflected_xss": {
            "question": """search_query = request.args.get('q')
return f"<h1>You searched for: {search_query}</h1>" """,
            "correct": "8"
        }
    }

    options = [
        "Buffer Overflow", "Race Condition", "Improper Input Validation", 
        "Clickjacking", "Side Channel Attack", "Broken Authentication", 
        "Code Injection", "Reflected XSS"
    ]

    print("Hard difficulty selected...")
    score = ask_questions(questions, options)

    if score == 5:
        clear_screen()
        print("Congratulations! You have completed the hard difficulty level.")
        crypto += 30
    else:
        clear_screen()
        print("You have failed the hard difficulty level. Please try again.")

    ready()

if __name__ == "__main__":
    ready()

