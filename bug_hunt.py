#!/usr/bin/env python3.11
import random
import subprocess
import shlex
import time
import platform

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
    introduction = """\
In this game, you play a computer hacker who's bug bounty hunting for a company.
The goal here is to accurately identify each vulnerability. You will be scored on a scale
of 1-5, with 5 being the highest possible score. Best of luck. (Type "exit" to quit)
"""
    print(introduction)
    level = "Pick a level:\n 1. Easy\n 2. Medium\n 3. Hard\n-> "
    difficulty = input(level).strip()

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
    questions = {
        "sql_injection": """user_input = input("Enter your username: ")
query = f"SELECT * FROM users WHERE username = '{user_input}';""",
        "xss": """<div>Welcome, <?php echo $_GET['username']; ?></div>""",
        "file_inclusion": """$file = $_GET['file'];
include($file);""",
        "command_injection": """$url = $_GET['url'];
system($url);""",
        "insecure_deserialization": """import pickle
data = pickle.loads(request.data)"""
    }

    options = ["SQL Injection", "XSS", "File Inclusion", "Command Injection", "Insecure Deserialization"]
    questions = {k.lower(): v for k, v in questions.items()}
    option_mapping = {k: str(i + 1) for i, k in enumerate(questions.keys())}

    print("Easy difficulty selected...")
    score = 0

    for i in range(5):
        correct_key, question = random.choice(list(questions.items()))
        correct_answer = option_mapping[correct_key]
        print(f"\nSnippet {i + 1}:\n{question}")
        print("\nOptions: 1. SQL Injection, 2. XSS, 3. File Inclusion, 4. Command Injection, 5. Insecure Deserialization")
        answer = input("Your answer (1-5): ").strip()
        
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
    else:
        print("You have failed the easy difficulty level. Please try again.")

    ready()

def medium_difficulty():
    questions = {
        "csrf": """<form action="/transfer" method="POST">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="to_account" value="123456">
</form>""",
        "file upload": '''move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $_FILES['file']['name']);''',
        "hardcoded credentials": '''$username = "admin"; $password = "admin";''',
        "xxe": """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><tag>&xxe;</tag>""",
        "weak cryptography": """from Crypto.Cipher import DES
cipher = DES.new('8bytekey', DES.MODE_ECB)"""
    }

    options = ["csrf", "file upload", "hardcoded credentials", "xxe", "weak cryptography"]
    questions = {k.lower(): v for k, v in questions.items()}
    option_mapping = {k: str(i + 1) for i, k in enumerate(questions.keys())}

    print("Medium difficulty selected...")
    score = 0

    for i in range(5):
        correct_key, question = random.choice(list(questions.items()))
        correct_answer = option_mapping[correct_key]
        print(f"\nSnippet {i + 1}:\n{question}")
        print("Options: 1. csrf, 2. file upload, 3. hardcoded credentials, 4. xxe, 5. weak cryptography")
        answer = input("Your answer (1-5): ").strip()

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
    else:
        clear_screen()
        print("You have failed the medium difficulty level. Please try again.")

    ready()

def hard_difficulty():
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
        "ldap injection": """query = f"(&(uid={user_input})(objectClass=person))"""
    }

    options = ["buffer overflow", "race condition", "improper input validation", "clickjacking", "ldap injection"]
    questions = {k.lower(): v for k, v in questions.items()}
    option_mapping = {k: str(i + 1) for i, k in enumerate(questions.keys())}

    score = 0

    for i in range(5):
        correct_key, question = random.choice(list(questions.items()))
        correct_answer = option_mapping[correct_key]
        print(f"\nSnippet {i + 1}:\n{question}")
        print("Options: 1. buffer overflow, 2. race condition, 3. improper input validation, 4. clickjacking, 5. ldap injection")
        answer = input("Your answer (1-5): ").strip()

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
    else:
        clear_screen()
        print("You have failed the hard difficulty level. Please try again.")

    ready()

if __name__ == "__main__":
    ready()

