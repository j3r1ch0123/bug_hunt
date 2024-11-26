#!/usr/bin/env python3.11
import random
import subprocess
import time
import platform
import os
import sys
import tkinter as tk

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
    def __init__(self, root):
        self.root = root
        self.root.title("Bug Hunt Game")
        self.output_text = tk.Text(self.root)
        self.output_text.pack()

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

    def get_question(self):
        if self.questions_asked < 5:
            question_set = self.questions[self.difficulty]  # Ensure this accesses the correct set
            self.correct_answer = random.choice(list(question_set.keys()))
            self.current_question = question_set[self.correct_answer]

            num_options = min(len(question_set), 8)
            self.current_options = random.sample(list(question_set.keys()), num_options)

            if self.correct_answer not in self.current_options:
                self.current_options[-1] = self.correct_answer

            self.questions_asked += 1

            return self.current_question, [opt.replace("_", " ").title() for opt in self.current_options]
        
        return None, None  # Return None if no questions left

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

    def ready(self):
        self.clear_screen()
        
        # Instructions
        self.output_text.insert(tk.END, "Welcome to Bug Hunt!\n")
        
        # Difficulty dropdown menu
        self.difficulty_label = tk.Label(self.root, text="Choose Difficulty:")
        self.difficulty_label.pack()

        self.difficulty_var = tk.StringVar(value="easy")  # Set default value
        self.difficulty_menu = tk.OptionMenu(self.root, self.difficulty_var, "easy", "medium", "hard")
        self.difficulty_menu.pack(fill=tk.X)  # Make it fill the width

        self.start_button = tk.Button(self.root, text="Start Game", command=self.start_game_button)
        self.start_button.pack(pady=10)

    def start_game_button(self):
        difficulty = self.difficulty_var.get()
        if difficulty:
            if self.bug_hunt.start_game(difficulty):  # Corrected method call
                self.output_text.delete(1.0, tk.END)  # Clear existing text
                self.play_game()  # Start the first question display
            else:
                print("Invalid difficulty selected.")

    def start_game(self, difficulty):
        if difficulty in self.questions:
            self.difficulty = difficulty  # Set the difficulty
            self.questions_asked = 0
            return True
        return False

    def play_game(self):
        self.output_text.delete(1.0, tk.END)  # Clear the output text area
        question, options = self.get_question()

        if question:
            self.output_text.insert(tk.END, "Vulnerability code:\n")
            self.output_text.insert(tk.END, question + "\n")
            self.output_text.insert(tk.END, "\nChoose the vulnerability type:")

            for i, option in enumerate(options, 1):
                self.output_text.insert(tk.END, f"{i}. {option}\n")

            self.answer_button = tk.Button(self.root, text="Submit Answer", command=lambda: self.check_answer_button(options))
            self.answer_button.pack()
        else:
            self.output_text.insert(tk.END, "Game Over! Final Score: {self.crypto} BTC")
            self.answer_button["state"] = "disabled"
            
    def check_answer_button(self, options):
        selected_answer = options[0]  # Let's assume the first option is selected for now
        correct = self.check_answer(selected_answer)

        if correct and not self.is_game_complete():
            self.play_game()

        else:
            self.end_game()

    def end_game(self):
        self.output_text.insert(tk.END, "\nGame over! Your final score: " + str(self.crypto) + " BTC\n")
        self.answer_button["state"] = "disabled"

    def exit_game(self):
        self.root.quit()
        
class Game:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Bug Hunt Game")
        # Set geometry to full screen
        self.root.geometry("{0}x{1}+0+0".format(self.root.winfo_screenwidth(), self.root.winfo_screenheight()))
        self.root.minsize(800, 600)
        self.root.configure(bg="#000000")  # Set the root background to black

        self.bug_hunt = BugHunt(self.root)

        # Main frame for layout organization
        self.main_frame = tk.Frame(self.root, bg="#000000")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Output text area
        self.output_text = tk.Text(self.main_frame, bg="#000000", fg="#ffffff")
        self.output_text.pack(fill=tk.BOTH, expand=True)  # This should fill the available space

        # Frame for the difficulty selection and start button
        self.difficulty_frame = tk.Frame(self.main_frame, bg="#000000")
        self.difficulty_frame.pack(pady=20, fill=tk.X)  # Fill horizontally

        # Difficulty selection
        self.difficulty_label = tk.Label(self.difficulty_frame, text="Choose Difficulty:", bg="#000000", fg="#ffffff")
        self.difficulty_label.pack(side=tk.LEFT)

        self.difficulty_var = tk.StringVar(value="easy")
        self.difficulty_menu = tk.OptionMenu(self.difficulty_frame, self.difficulty_var, "easy", "medium", "hard")
        self.difficulty_menu.pack(side=tk.LEFT, fill=tk.X, expand=True)  # Fill the width

        self.start_button = tk.Button(self.difficulty_frame, text="Start Game", command=self.start_game, bg="black", fg="#ffffff")
        self.start_button.pack(side=tk.LEFT, padx=5)  # Add some padding

        # Call the `ready()` method to set up the game interface
        self.bug_hunt.ready()

        # Frame for answer buttons
        self.answer_frame = tk.Frame(self.main_frame, bg="#000000")
        self.answer_frame.pack(pady=20, fill=tk.X)  # Fill horizontally

        # Creating the answer buttons
        self.answer_buttons = []
        for i in range(8):
            button = tk.Button(self.answer_frame, text=f"Answer {i + 1}", command=lambda i=i: self.check_answer(i), bg="black", fg="white")
            button.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)  # Fill and expand
            self.answer_buttons.append(button)

        # Frame for exit button
        self.exit_frame = tk.Frame(self.main_frame, bg="#000000")
        self.exit_frame.pack(pady=20)

        # Exit button
        self.exit_button = tk.Button(self.exit_frame, text="Exit", command=self.bug_hunt.exit_game, bg="black", fg="white")
        self.exit_button.pack()

        # Frame for score and output
        self.score_frame = tk.Frame(self.main_frame, bg="#000000")
        self.score_frame.pack(pady=20)

        # Display the score
        self.score_label = tk.Label(self.score_frame, text=f"Score: {self.bug_hunt.crypto}", font=("Arial", 14), bg="#000000", fg="#ffffff")
        self.score_label.pack(pady=5)

        # Redirect stdout to the text widget
        sys.stdout = RedirectText(self.output_text)

        self.root.mainloop()

    def start_game(self):
        difficulty = self.difficulty_var.get()  # Get selected difficulty
        if difficulty:
            if self.bug_hunt.start_game(difficulty):  # Call BugHunt's start_game
                self.output_text.delete(1.0, tk.END)  # Clear existing text
                self.display_question()  # Start the first question display
            else:
                print("Invalid difficulty selected.")

    def display_question(self):
        question, options = self.bug_hunt.get_question()
        if question:
            self.output_text.delete(1.0, tk.END)  # Clear previous output
            self.output_text.insert(tk.END, question + "\n\n")

            # Update button texts and states
            for i, option in enumerate(options):
                self.answer_buttons[i].config(text=option, bg="black", state=tk.NORMAL)

            for i in range(len(options), len(self.answer_buttons)):
                self.answer_buttons[i].config(state=tk.DISABLED)  # Disable unused buttons
        else:
            self.output_text.insert(tk.END, "Game Over!\n")
            for button in self.answer_buttons:
                button.config(state=tk.DISABLED)  # Disable all buttons at the end

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
    game.display_question()