#!/usr/bin/env python3.11
import random
import subprocess
import shlex

def ready():
    introduction = """\
This is a text-based game for bug bounty hunters. There are three levels:
easy, medium, and hard. The goal of this game is to go through 5 different
snippets of vulnerable code and identify each vulnerability.
"""
    print(introduction)
    level = "Pick a level:\n 1. Easy\n 2. Medium\n 3. Hard\n"
    difficulty = input(level)
    if difficulty == "1":
        easy_difficulty()
    elif difficulty == "2":
        medium_difficulty()
    elif difficulty == "3":
        hard_difficulty()
    else:
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
    # Create a mapping from vulnerability type to its option number
    option_mapping = {k: str(i + 1) for i, k in enumerate(questions.keys())}

    print("Easy difficulty selected...")
    score = 0

    # Loop 5 times
    for i in range(5):
        correct_key, question = random.choice(list(questions.items()))
        correct_answer = option_mapping[correct_key]  # Get the correct answer as number
        print(f"\nSnippet {i + 1}:\n{question}")
        print("\nOptions: 1. SQL Injection, 2. XSS, 3. File Inclusion, 4. Command Injection, 5. Insecure Deserialization")
        answer = input("Your answer (1-5): ")
        
        if answer == correct_answer:
            # check which os is being used
            if subprocess.check_output(shlex.split("uname -s")) == b'Linux\n':
                subprocess.run(shlex.split("clear"))
            else:
                subprocess.run(shlex.split("cls"))
            print("Correct!")
            score += 1
        else:
            # check which os is being used
            if subprocess.check_output(shlex.split("uname -s")) == b'Linux\n':
                subprocess.run(shlex.split("clear"))
            else:
                subprocess.run(shlex.split("cls"))
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
    option_mapping = {k: str(i + 1) for i, k in enumerate(questions.keys())}

    print("Medium difficulty selected...")
    score = 0
    for i in range(5):
        correct_key, question = random.choice(list(questions.items()))
        correct_answer = option_mapping[correct_key]  # Get the correct answer as number
        print(f"\nSnippet {i + 1}:\n{question}")
        print("Options: 1. csrf, 2. file upload, 3. hardcoded credentials, 4. xxe, 5. weak cryptography")
        answer = input("Your answer (1-5): ")

        if answer == correct_answer:
            if subprocess.check_output(shlex.split("uname -s")) == b'Linux\n':
                subprocess.run(shlex.split("clear"))
            else:
                subprocess.run(shlex.split("cls"))
            print("Correct!")
            score += 1
        else:
            if subprocess.check_output(shlex.split("uname -s")) == b'Linux\n':
                subprocess.run(shlex.split("clear"))
            else:
                subprocess.run(shlex.split("cls"))
            print(f"Incorrect. The correct answer is: {correct_answer}")
        print(f"Score: {score}/5")

    if score == 5:
        if subprocess.check_output(shlex.split("uname -s")) == b'Linux\n':
            subprocess.run(shlex.split("clear"))
        else:
            subprocess.run(shlex.split("cls"))
        print("Congratulations! You have completed the medium difficulty level.")
    else:
        if subprocess.check_output(shlex.split("uname -s")) == b'Linux\n':
            subprocess.run(shlex.split("clear"))
        else:
            subprocess.run(shlex.split("cls"))
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
        "ldap injection": """ldap_query = f"(&(uid={user_input})(objectClass=person))"""
    }

    options = ["buffer overflow", "race condition", "improper input validation", "clickjacking", "ldap injection"]
    # Create a mapping from vulnerability type to its option number
    option_mapping = {k: str(i + 1) for i, k in enumerate(questions.keys())}

    score = 0  # Initialize score
    for i in range(5):
        correct_key, question = random.choice(list(questions.items()))
        correct_answer = option_mapping[correct_key]  # Get the correct answer as number
        print(f"\nSnippet {i + 1}:\n{question}")
        print("Options: 1. buffer overflow, 2. race condition, 3. improper input validation, 4. clickjacking, 5. ldap injection")
        answer = input("Your answer: ")

        if answer == correct_answer:
            # check which os is being used
            if subprocess.check_output(shlex.split("uname -s")) == b'Linux\n':
                subprocess.run(shlex.split("clear"))
            else:
                subprocess.run(shlex.split("cls"))
            print("Correct!")
            score += 1
        else:
            # check which os is being used
            if subprocess.check_output(shlex.split("uname -s")) == b'Linux\n':
                subprocess.run(shlex.split("clear"))
            else:
                subprocess.run(shlex.split("cls"))
            print(f"Incorrect. The correct answer is: {correct_answer}")
        
        print(f"Score: {score}/5")

    if score == 5:
        # check which os is being used
        if subprocess.check_output(shlex.split("uname -s")) == b'Linux\n':
            subprocess.run(shlex.split("clear"))
        else:
            subprocess.run(shlex.split("cls"))

        print("Congratulations! You have completed the hard difficulty level.")

    else:
        # check which os is being used
        if subprocess.check_output(shlex.split("uname -s")) == b'Linux\n':
            subprocess.run(shlex.split("clear"))
        else:
            subprocess.run(shlex.split("cls"))

        print("You have failed the hard difficulty level. Please try again.")

    ready()

if __name__ == "__main__":
    ready()