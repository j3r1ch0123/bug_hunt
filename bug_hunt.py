#!/usr/bin/env python3.11
import random
import subprocess
import time
import platform
import os
import sys
import tkinter as tk

crypto = 0

class RedirectText:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        self.text_widget.after(0, self._append_text, message)

    def _append_text(self, message):
        self.text_widget.insert(tk.END, message)
        self.text_widget.see(tk.END)

    def flush(self):
        pass

class BugHunt:
    def __init__(self):
        self.questions = {
            "easy": {
                "sql_injection": """user_print = input("Enter your username: ")
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
        return redirect(next_url)""",
                "hardcoded_api_key": """api_key = "12345-ABCDE-67890"
    response = requests.get(f"https://api.example.com/data?key={api_key}")""",
                "directory_transversal": """\
    file_path = "/var/www/html/" + input("Enter the file name: ")
    with open(file_path, 'r') as file:
        data = file.read()""",
            },
            "medium": {
                "csrf": """<form action="/transfer" method="POST">
        <print type="hidden" name="amount" value="1000">
        <print type="hidden" name="to_account" value="123456">
    </form>""",
                "file_upload": '''move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $_FILES['file']['name']);''',
                "hardcoded_credentials": '''$username = "admin"; $password = "admin";''',
                "xxe": """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><tag>&xxe;</tag>""",
                "weak_cryptography": """from Crypto.Cipher import DES
    cipher = DES.new('8bytekey', DES.MODE_ECB)""",
                "ssrf": """import requests
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
                "path_transversal": """from flask import Flask, send_from_directory, request

    app = Flask(__name__)

    @app.route('/download')
    def download():
        filename = request.args.get('file')
        return send_from_directory('/secure_directory', filename)""",
                "insecure_jwt_implementation": """import jwt
    token = jwt.encode({"user": "admin"}, "secret", algorithm="HS256")""",
            },
            "hard": {
                "buffer_overflow": """void vulnerable_function(char *user_input) {
        char buffer[10];
        strcpy(buffer, user_input);
    }""",
                "race_condition": """def transfer(from_account, to_account, amount):
        balance = get_balance(from_account)
        if balance >= amount:
            set_balance(from_account, balance - amount)
            set_balance(to_account, get_balance(to_account) + amount)""",
                "improper_input_validation": """int validate_user(int user_id) {
        if (user_id > 0) {
            return 1;
        }
        return 0;
    }""",
                "clickjacking": """<iframe src="http://vulnerable-site.com" style="opacity:0;"></iframe>""",
                "ldap_injection": """query = f"(&(uid={user_input})(objectClass=person))""",
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
            return f'Decrypted data: {plaintext}'
        except ValueError:
            return 'Decryption failed due to padding error', 400""",
                "use_after_free": """#include <stdio.h>
    #include <stdlib.h>

    int main() {
        int *ptr = malloc(sizeof(int));
        *ptr = 5;
        free(ptr);
        printf("%d\n", *ptr);
        return 0;
    }""",
                "integer_overflow": """\
    int add(int a, int b) {
        return a + b;
    }
    int main() {
        int x = 2147483647;
        int y = 1;
        printf("%d\n", add(x, y));  // This overflows
    }
    """,
            },
        }

        self.current_question = None
        self.current_options = []
        self.correct_answer = None
        self.crypto = 0
        self.questions_asked = 0

    def start_game(self, difficulty):
        if difficulty in self.questions:
            self.difficulty = difficulty
            self.questions_asked = 0
            self.crypto = 0
            return True
        return False

    def get_question(self):
        if self.questions_asked < 5:
            question_set = self.questions[self.difficulty]  # Fixed to use 'self.questions'
            self.correct_answer = random.choice(list(question_set.keys()))
            self.current_question = question_set[self.correct_answer]
            num_options = min(len(question_set), 8)
            self.current_options = random.sample(list(question_set.keys()), num_options)  # Fixed to use 'question_set'
            if self.correct_answer not in self.current_options:
                self.current_options[-1] = self.correct_answer
            self.questions_asked += 1
            return self.current_question, [opt.replace("_", " ").title() for opt in self.current_options]
        return None, None

    def check_answer(self, selected_answer):
        if selected_answer == self.correct_answer.replace("_", " ").title():
            self.crypto += 10
            print("Correct!")
            # Delete the answered question from the dictionary
            del self.questions[self.difficulty][self.correct_answer]
            return True
        else:
            print(f"Incorrect, the correct answer was: {self.correct_answer}")
            return False

    def is_game_complete(self):
        return self.questions_asked >= 5

    def clear_screen(self):
        """Clear the screen based on the operating system."""
        os_name = platform.system()
        if os_name in ["Linux", "Darwin"]:
            subprocess.run(["clear"])
        elif os_name == "Windows":
            subprocess.run(["cls"], shell=True)
        else:
            print("\n" * 100)

    def play_difficulty(self, difficulty):
        questions = self.questions[difficulty]
        options = list(questions.keys())
        score = 0

        for i in range(5):
            correct_key = random.choice(options)
            question = questions[correct_key]
            print(f"\nSnippet {i + 1}:\n{question}")
            print("Options: " + ", ".join(f"{idx + 1}. {opt.replace('_', ' ').title()}" for idx, opt in enumerate(options)))
            answer = input("Your answer (1-8): ").strip()

            if options[int(answer) - 1] == correct_key:
                self.clear_screen()
                print("Correct!")
                score += 1
            else:
                self.clear_screen()
                print(f"Incorrect. The correct answer is: {correct_key.replace('_', ' ').title()}")
            print(f"Score: {score}/5")

        return score

    def ready(self):
        global crypto
        print("Welcome to Bug Hunt!")
        print("In this game, you're a computer hacker participating in a digital heist.")
        print("To earn crypto, identify vulnerabilities in the code.")
        print("(Type 'exit' to quit)")
        print(f"Current crypto: {crypto} BTC")
        level = input("Pick a level:\n 1. Easy\n 2. Medium\n 3. Hard\n-> ")

        if level == "1":
            self.clear_screen()
            score = self.play_difficulty("easy")
            if score == 5:
                print("Congratulations! You have completed the easy difficulty level.")
                crypto += 10
            else:
                print("You have failed the easy difficulty level. Please try again.")
        elif level == "2":
            self.clear_screen()
            score = self.play_difficulty("medium")
            if score == 5:
                print("Congratulations! You have completed the medium difficulty level.")
                crypto += 20
            else:
                print("You have failed the medium difficulty level. Please try again.")
        elif level == "3":
            self.clear_screen()
            score = self.play_difficulty("hard")
            if score == 5:
                print("Congratulations! You have completed the hard difficulty level.")
                crypto += 40
            else:
                print("You have failed the hard difficulty level. Please try again.")
        elif level.lower() == "exit":
            self.clear_screen()
            print("Exiting game in 5 seconds, thanks for playing...")
            time.sleep(5)
            exit()
        else:
            self.clear_screen()
            print("Invalid print. Please try again.")
            self.ready()
        
class Game:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Bug Hunt Game")
        self.root.geometry("1200x1000")
        self.root.configure(bg="#f0f0f0")

        self.bug_hunt = BugHunt()
        self.difficulty_var = tk.StringVar(value="Select Difficulty")
        self.difficulty_options = ["Easy", "Medium", "Hard"]

        self.difficulty_menu = tk.OptionMenu(self.root, self.difficulty_var, *self.difficulty_options)
        self.difficulty_menu.pack(pady=20)

        self.start_button = tk.Button(self.root, text="Start", command=self.start_game)
        self.start_button.pack(pady=10)

        # Display the score
        self.score_label = tk.Label(self.root, text=f"Score: 0", font=("Arial", 14), bg="#000000", fg="white")
        self.score_label.pack(pady=5)

        self.output_text = tk.Text(self.root, font=("Arial", 12), bg="#000000", fg="#ffffff", wrap=tk.WORD)
        self.output_text.pack(pady=10, fill=tk.BOTH, expand=True)

        sys.stdout = RedirectText(self.output_text)

        # Creating the answer buttons
        self.answer_buttons = [tk.Button(self.root, text=f"Answer {i + 1}", command=lambda i=i: self.check_answer(i), bg="lightgray", fg="black") for i in range(8)]
        for button in self.answer_buttons:
            button.pack(side=tk.LEFT, padx=5)

        self.root.mainloop()

    def start_game(self):
        difficulty = self.difficulty_var.get().lower()
        if self.bug_hunt.start_game(difficulty):
            self.display_question()
        else:
            print("Please select a valid difficulty level.")

    def display_question(self):
        question, options = self.bug_hunt.get_question()
        if question:
            # Clear previous output and display the new question
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, question + "\n\n")

            # Update button texts and states
            for i, option in enumerate(options):
                self.answer_buttons[i].config(text=option, bg="lightgray", state=tk.NORMAL)

            # Disable buttons that aren't needed
            for i in range(len(options), len(self.answer_buttons)):
                self.answer_buttons[i].config(state=tk.DISABLED)  # Keep the button, but disable it
        else:
            self.output_text.insert(tk.END, "Game Over!\n")
            # Disable all answer buttons when the game is over
            for button in self.answer_buttons:
                button.config(state=tk.DISABLED)

    def check_answer(self, answer_index):
        selected_answer = self.answer_buttons[answer_index].cget("text")
        correct = self.bug_hunt.check_answer(selected_answer)

        # Update the score label
        self.score_label.config(text=f"Score: {self.bug_hunt.crypto}")

        # After checking the answer, move on to the next question
        if not self.bug_hunt.is_game_complete():
            self.display_question()
        else:
            self.output_text.insert(tk.END, f"Game Over! Final Score: {self.bug_hunt.crypto}\n")
            # Disable all answer buttons when the game is over
            for button in self.answer_buttons:
                button.config(state=tk.DISABLED)

if __name__ == "__main__":
    game = Game()
    game.start_game()