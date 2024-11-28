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
        self.questions_asked = 0
        self.crypto = 0
        self.current_question = None
        self.current_options = []
        self.correct_answer = None
        self.difficulty = None  # Initially no difficulty set
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

    def set_difficulty(self, difficulty):
        """Set the difficulty for the game."""
        if difficulty in self.questions:
            self.difficulty = difficulty
            print(f"Difficulty set to: {self.difficulty}")  # Debugging
        else:
            raise ValueError(f"Invalid difficulty: {difficulty}")

    def get_question(self):
        """Return the next question based on the current difficulty."""
        if not self.difficulty:
            raise ValueError("Difficulty is not set or invalid.")

        if self.questions_asked < 5:
            question_set = self.questions[self.difficulty]
            self.correct_answer = random.choice(list(question_set.keys()))
            self.current_question = question_set[self.correct_answer]

            num_options = min(len(question_set), 8)
            self.current_options = random.sample(list(question_set.keys()), num_options)

            if self.correct_answer not in self.current_options:
                self.current_options[-1] = self.correct_answer

            self.questions_asked += 1

            return self.current_question, [opt.replace("_", " ").title() for opt in self.current_options]

        return None, None  # No more questions left

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

    def reset(self):
        """Reset the game state to allow a new game to start."""
        self.questions_asked = 0
        self.crypto = 0
        self.current_question = None
        self.current_options = []
        self.correct_answer = None
        print("Game has been reset.")  # Debug print


class Game:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Bug Hunt Game")
        self.difficulty_var = tk.StringVar(value="easy")  # Default to easy difficulty
        difficulty_menu = tk.OptionMenu(self.root, self.difficulty_var, "easy", "medium", "hard")
        difficulty_menu.pack()

        self.bug_hunt = BugHunt(self.root)

        # Create frames for better layout
        self.top_frame = tk.Frame(self.root, bg="gray", height=400)
        self.top_frame.pack(fill=tk.BOTH, expand=True)
        self.bottom_frame = tk.Frame(self.root, height=100, bg="darkgray")
        self.bottom_frame.pack(fill=tk.X, side=tk.BOTTOM)

        # Output text box in the top frame
        self.output_text = tk.Text(self.top_frame, bg="black", fg="green")
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Start button in the bottom frame
        self.start_button = tk.Button(self.bottom_frame, text="Start Game", command=self.ready_game)
        self.start_button.pack(side=tk.BOTTOM, pady=10)

        sys.stdout = RedirectText(self.output_text)
        self.root.mainloop()

    def clear_screen(self):
        # Clear the output text box
        self.output_text.delete(1.0, tk.END)

        # Destroy any dynamically created buttons or widgets
        if hasattr(self, 'answer_buttons'):
            for btn in self.answer_buttons:
                btn.destroy()

        # Optionally clear other frames or widgets (if needed)
        if hasattr(self, 'play_again_button') and self.play_again_button.winfo_exists():
            self.play_again_button.destroy()

    def ready_game(self):
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "Welcome to Bug Hunt!\n")

        # Difficulty selection menu
        difficulty_menu = tk.OptionMenu(self.bottom_frame, self.difficulty_var, "easy", "medium", "hard")
        difficulty_menu.pack(side=tk.TOP, pady=10)

        self.confirm_button = tk.Button(self.bottom_frame, text="Confirm Difficulty", command=self.start_game)
        self.confirm_button.pack(side=tk.TOP)

        self.bug_hunt.reset()

    def start_game(self):
        difficulty = self.difficulty_var.get()  # Get difficulty value from difficulty_var
        print(f"Selected difficulty: {difficulty}")  # Debugging
        
        self.bug_hunt.set_difficulty(difficulty)  # Set difficulty in BugHunt
        
        self.output_text.delete(1.0, tk.END)  # Clear the text
        self.play_game()

    def play_game(self):
        question, options = self.bug_hunt.get_question()
        if question:
            self.output_text.insert(tk.END, f"\nVulnerability Code:\n{question}\n")
            self.output_text.insert(tk.END, "\nChoose the vulnerability type:\n")
            
            # Destroy previous answer buttons if they exist
            if hasattr(self, 'answer_buttons'):
                for btn in self.answer_buttons:
                    btn.destroy()

            # Create new answer buttons
            self.answer_buttons = [
                tk.Button(self.bottom_frame, text=opt, command=lambda o=opt: self.check_answer(o), bg="black", fg="white")
                for opt in options
            ]

            for btn in self.answer_buttons:
                btn.pack(side=tk.LEFT, padx=5, pady=10)
        else:
            self.output_text.insert(tk.END, f"\nGame Over! Final Score: {self.bug_hunt.crypto} BTC\n")
            self.show_play_again_button()

    def check_answer(self, selected_answer):
        self.clear_screen()
        if self.bug_hunt.check_answer(selected_answer):
            self.output_text.insert(tk.END, "Correct!\n")
        else:
            self.output_text.insert(tk.END, f"Incorrect! The correct answer was: {self.bug_hunt.correct_answer}\n")
        
        # Destroy current answer buttons
        for btn in self.answer_buttons:
            btn.destroy()
        
        if self.bug_hunt.is_game_complete():
            self.output_text.insert(tk.END, f"\nGame Over! Final Score: {self.bug_hunt.crypto} BTC\n")
            self.show_play_again_button()
        else:
            self.play_game()

    def show_play_again_button(self):
        """Show a play again button when the game ends."""
        if not hasattr(self, 'play_again_button') or self.play_again_button is None:  # Only create the button once
            self.play_again_button = tk.Button(self.root, text="Play Again", command=self.play_again)
            self.play_again_button.pack(pady=10)

    def play_again(self):
        """Reset the game state and start a new game."""
        self.bug_hunt.reset()  # Reset the game state in BugHunt
        self.output_text.delete(1.0, tk.END)  # Clear the text box
        self.play_again_button.pack_forget()  # Remove the "Play Again" button
        self.start_game()  # Start a new game

if __name__ == "__main__":
    game = Game()
