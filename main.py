import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import random
import string

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")

        # Entry variables
        self.length_var = tk.StringVar(value="12")
        self.uppercase_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.special_chars_var = tk.BooleanVar(value=True)

        # Widgets
        self.create_widgets()

        # Configure rows and columns for responsiveness
        for i in range(7):
            self.root.grid_rowconfigure(i, weight=1)
            self.root.grid_columnconfigure(0, weight=1)
            self.root.grid_columnconfigure(1, weight=1)

    def create_widgets(self):
        # Labels
        ttk.Label(self.root, text="Password Length:").grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        # Entry
        ttk.Entry(self.root, textvariable=self.length_var, width=5).grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

        # Checkboxes
        ttk.Checkbutton(self.root, text="Include Uppercase", variable=self.uppercase_var).grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        ttk.Checkbutton(self.root, text="Include Digits", variable=self.digits_var).grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        ttk.Checkbutton(self.root, text="Include Special Characters", variable=self.special_chars_var).grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

        # Button
        ttk.Button(self.root, text="Generate Password", command=self.generate_password).grid(row=5, column=0, columnspan=2, pady=10, sticky="nsew")

        # Password label
        ttk.Label(self.root, text="Generated Password:").grid(row=6, column=0, padx=10, pady=5, sticky="nsew")

        # Password entry
        self.password_entry = ttk.Entry(self.root, show="*", state="readonly")
        self.password_entry.grid(row=6, column=1, padx=10, pady=5, sticky="nsew")

        # Show/Hide button
        ttk.Button(self.root, text="Show/Hide", command=self.toggle_password_visibility).grid(row=7, column=0, columnspan=2, pady=5, sticky="nsew")

    def generate_password(self):
        try:
            length = int(self.length_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid input for password length")
            return

        include_uppercase = self.uppercase_var.get()
        include_digits = self.digits_var.get()
        include_special_chars = self.special_chars_var.get()

        characters = string.ascii_lowercase
        if include_uppercase:
            characters += string.ascii_uppercase
        if include_digits:
            characters += string.digits
        if include_special_chars:
            characters += string.punctuation

        if length < 1:
            messagebox.showerror("Error", "Password length must be at least 1")
            return

        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_visible = False  # Reset visibility when generating a new password
        self.update_password_entry(password)

    def toggle_password_visibility(self):
        if self.password_visible:
            self.password_entry.config(show="*")
        else:
            self.password_entry.config(show="")
        self.password_visible = not self.password_visible

    def update_password_entry(self, password):
        self.password_entry.config(state="normal")
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.password_entry.config(state="readonly")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
