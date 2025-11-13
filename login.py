
import time
import tkinter as tk
import ttkbootstrap as ttks
from tkinter import messagebox
import os
from encryption_decryption import EncryptionDecryption
import re

default_profile = """### ACCOUNTS\n\n### API\nAPI = \n### PASSWORD\nPASSWORD = \n### THEME\nTHEME = darkly"""


class LoginPage:
    def __init__(self, master_window):
        self.window = ttks.Toplevel(master_window)
        self.window.title("Login")
        self.window.geometry("300x220")
        self.frame = tk.Frame(self.window)
        self.frame.grid(row=0, column=0, pady=20, padx=70)

        tk.Label(self.frame, text="Username").pack()
        self.username_Entry = tk.Entry(self.frame)
        self.username_Entry.pack()
        tk.Label(self.frame, text="Password").pack()
        self.password_Entry = tk.Entry(self.frame)
        self.password_Entry.pack()
        self.button_frame = tk.Frame(self.window)
        self.button_frame.grid(row=1, column=0)
        self.login_button = ttks.Button(self.button_frame, text="Login", bootstyle="info", command=self.login)
        self.login_button.pack(side="left", padx=5)
        self.new_user = ttks.Button(self.button_frame, text="New Profile", bootstyle="info", command=self.new_user)
        self.new_user.pack(side="left", padx=5)
        self.message_label = tk.Label(self.frame)
        self.message_label.pack()
        self.found_username = False
        self.login_successful = False
        self.master = master_window
        self.decrypted_data = None
        self.encrypt_decrypt = None

    def login(self):
        self.find_username()
        if self.found_username:
            result = self.find_password()
            if result == "Wrong Password":
                self.message_label.config(text="Wrong password", fg="red")
            else:
                self.message_label.config(text="Login successful", fg="green")
                self.login_successful = True
                self.decrypted_data = result
                time.sleep(0.5)
                self.window.destroy()
                self.master.deiconify()

    def find_username(self):
        self.found_username = False
        profiles = []
        for x in os.listdir():
            if "profile" in x:
                profiles.append(x)
        username = self.username_Entry.get()
        for profile in profiles:
            if "enc" in profile:
                profile_name = profile.split("_")
                profile_name = profile_name[0]
                if username != profile_name:
                    pass
                else:
                    self.found_username = True

        if not self.found_username:
            self.message_label.config(text="Username not found", fg="red")
            self.message_label.pack()

    def find_password(self):
        username = self.username_Entry.get()
        password = self.password_Entry.get()
        encrypt_decrypt = EncryptionDecryption(username=username, password=password)
        self.encrypt_decrypt = encrypt_decrypt
        if encrypt_decrypt.decrypt_file_with_password() == "Decryption didn't work":
            return "Wrong Password"
        else:
            return encrypt_decrypt.decrypt_file_with_password()

    def write_to_file(self, list):
        self.encrypt_decrypt.encrypt_file_with_password(input_data=list)

    def new_user(self):
        self.window.withdraw()
        new_user_window = ttks.Toplevel(self.window)
        new_user_window.title("Create A New Profile")
        new_user_window.geometry("300x220")
        new_user_window_frame = tk.Frame(new_user_window)
        new_user_window_frame.grid(row=0, column=0, pady=20, padx=70)

        tk.Label(new_user_window_frame, text="Username").pack()
        new_user_window_username_Entry = tk.Entry(new_user_window_frame)
        new_user_window_username_Entry.pack()
        tk.Label(new_user_window_frame, text="Password").pack()
        new_user_window_password_Entry = tk.Entry(new_user_window_frame)
        new_user_window_password_Entry.pack()
        tk.Label(new_user_window_frame, text="Confirm Password").pack()
        new_user_window_confirm_Entry = tk.Entry(new_user_window_frame)
        new_user_window_confirm_Entry.pack()
        new_user_message_label = tk.Label(new_user_window_frame)
        new_user_message_label.pack()
        button_frame = tk.Frame(new_user_window)
        button_frame.grid(row=1, column=0)

        def cancel_button():
            new_user_window.destroy()
            self.window.deiconify()

        def create_button():
            global default_profile
            user_n = new_user_window_username_Entry.get()
            pass_w = new_user_window_password_Entry.get()
            confirm_pass = new_user_window_confirm_Entry.get()

            profiles = [x.split("_")[0] for x in os.listdir() if x.endswith(".enc")]

            if user_n == "":
                new_user_message_label.config(text="Username cannot be empty", fg="red")
            elif pass_w != confirm_pass:
                new_user_message_label.config(text="Passwords do not match", fg="red")
            elif len(pass_w) < 1:
                new_user_message_label.config(text="Password cannot be empty", fg="red")
            elif user_n in profiles:
                new_user_message_label.config(text="Username already exists", fg="red")
            else:
                encryption_decryption = EncryptionDecryption(username=user_n, password=pass_w)
                encryption_decryption.encrypt_file_with_password(input_data=default_profile)
                new_user_window.destroy()
                self.window.deiconify()

        new_user_window_register_button = ttks.Button(button_frame, text="Create", bootstyle="info",
                                                      command=create_button)
        new_user_window_register_button.pack(side="left", padx=5)
        new_user_window_cancel_button = ttks.Button(button_frame, text="Cancel", bootstyle="secondary",
                                                    command=cancel_button)
        new_user_window_cancel_button.pack(side="left", padx=5)
