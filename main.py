import sys
import os

if True:  

    import importlib.util
    spec = importlib.util.find_spec("ttkbootstrap.localization.msgs")
    if spec:
        msgs_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(msgs_module)
        
        original_init = msgs_module.initialize_localities
        def patched_init():
            try:
                original_init()
            except Exception as e:
                if 'msgcat' in str(e):
                    pass  
                else:
                    raise
        msgs_module.initialize_localities = patched_init
        sys.modules['ttkbootstrap.localization.msgs'] = msgs_module

import json
import random
import os

import json
import random
import os
import tkinter
from tkinter import ttk, Toplevel
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import os
import ttkbootstrap as ttks
import requests
import tkinter.scrolledtext as tkscrolled
from bs4 import BeautifulSoup
from login import LoginPage
import traceback
import hashlib
import re
import string

lowercase_letters_list = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                          'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

capital_letters_list = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

symbols_list = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+',
                '[', ']', '{', '}', '|', '\\', ';', ':', "'", '"', ',', '.', '<', '>',
                '/', '?', '~', '`']


def read_file():
    decrypted_data = login_window.decrypted_data
    password_local_list = []

    if not decrypted_data:
        return password_local_list

    try:
        start_index = None
        end_index = None

        for i, line in enumerate(decrypted_data):
            if "### ACCOUNTS" in line:
                start_index = i + 1
            elif "### API" in line:
                end_index = i
                break

        if start_index is None or end_index is None:
            return password_local_list

        for line in decrypted_data[start_index:end_index]:
            line = line.strip()
            if len(line) < 2 or "###" in line:
                continue

            if "Website:" in line:
                parts = line.split("|")
                if len(parts) == 3:
                    website = parts[0].replace("Website:", "").strip()
                    email = parts[1].replace("Emails:", "").strip()
                    password = parts[2].replace("Password:", "").strip()
                    password_local_list.append([website, email, password])

    except Exception as e:
        print(f"Error reading file: {e}")
        return []

    return password_local_list


try:
    current_theme = "darkly"
    window = ttks.Window(themename=current_theme)
    window.withdraw()

    login_window = LoginPage(window)
    login_window.window.wait_window()

    if not login_window.login_successful:
        print("Login cancelled or failed")

    # Apply the actual theme from the decrypted profile BEFORE creating widgets
    try:
        for line in login_window.decrypted_data:
            if line.strip().startswith("THEME ="):
                current_theme = line.strip().split("=", 1)[1].strip() or "darkly"
                break
    except Exception:
        current_theme = "darkly"

    window.style.theme_use(current_theme)
    window.minsize(width=520, height=200)
    window.resizable(width=False, height=False)
    window.config(pady=5)
    window.title("Password Manager")

    password_list = read_file()

except Exception as e:
    print(f"Initialization error: {e}")
    traceback.print_exc()


def write_file(pass_list):
    try:
        login_window.write_to_file(pass_list)
    except Exception as e:
        print(f"Error writing file: {e}")
        from tkinter import messagebox
        messagebox.showerror("Error", f"Failed to save passwords: {e}")


treeview = ttks.Treeview(
    columns=(
        "Website", "Email", "Password"),
    show="headings"
)
treeview.heading("Website", text="Website")
treeview.heading("Email", text="Email/Username")
treeview.heading("Password", text="Password")


def edit_button_func():
    selected_items = treeview.selection()
    item_index = treeview.index(selected_items[0])
    website = ""
    email = ""
    password = ""
    if selected_items:
        for item in selected_items:
            website = treeview.item(item, "values")[0]
            email = treeview.item(item, "values")[1]
            password = treeview.item(item, "values")[2]
        ADD_BUTTON(mode="Edit", index_of_item=item_index, website=website, email=email, password=password)


def delete_selected():
    selected_items = treeview.selection()
    item_index = treeview.index(selected_items[0])
    if selected_items:
        confirm_box = Toplevel()
        confirm_box.geometry("200x100")
        confirm_label = ttks.Label(confirm_box, text="Are you sure you want to delete?")
        confirm_label.pack(side="top", pady=10)

        def confirm_button_return():
            for item in selected_items:
                treeview.delete(item)
            try:
                password_list.pop(item_index)
            except:
                pass
            write_file(password_list)
            cancel_button_func()

        def cancel_button_func():
            confirm_box.destroy()
            confirm_box.update()

        confirm_button = ttks.Button(confirm_box, text="Delete", bootstyle="danger", command=confirm_button_return)
        cancel_button = ttks.Button(confirm_box, text="Cancel", bootstyle="secondary", command=cancel_button_func)
        confirm_button.pack(side="left", padx=(30, 10), pady=10)
        cancel_button.pack(side="left", padx=10, pady=10)


def populate(ps_list):
    for list in ps_list:
        treeview.insert(
            "",
            tkinter.END,
            values=(
                list[0],
                list[1],
                list[2]
            ),
        )


treeview.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

populate(password_list)


def repopulate(ps_list):
    id_list = treeview.get_children()
    for id in id_list:
        treeview.delete(id)
    populate(ps_list)


def get_char_func(num, list):
    return_list = []
    num = int(num)
    for i in range(num):
        return_list.append(random.choice(list))
    return return_list


def add_func():
    ADD_BUTTON()


def ADD_BUTTON(mode="", index_of_item=0, website="", email="", password=""):
    def is_it_a_num(event):
        value = length_entry.get()
        try:
            int(value)
            length_label.config(text="Length", fg="white")
            return True

        except ValueError:
            length_label.config(text="Not Number", fg="red")
            return False

    top = Toplevel()
    top.geometry("350x170")
    top.resizable(width=False, height=False)

    if mode == "Edit":
        top.title("Edit password")
    else:
        top.title("Add a new password")

    top.config(padx=50)
    website_name_label = tkinter.Label(top, text="Website Name")
    website_name_label.grid(padx=(0, 20), column=0, row=1)
    website_name_entry = tkinter.Entry(top)
    website_name_entry.grid(padx=(0, 20), column=0, row=2)
    website_name_entry.insert(0, website)
    email_label = tkinter.Label(top, text="Email/Username")
    email_label.grid(padx=(0, 20), column=0, row=3)
    email_entry = tkinter.Entry(top)
    email_entry.grid(padx=(0, 20), column=0, row=4)
    email_entry.insert(0, email)
    password_label = tkinter.Label(top, text="Password")
    password_label.grid(padx=(0, 20), column=0, row=5)
    password_entry = tkinter.Entry(top)
    password_entry.grid(padx=(0, 20), column=0, row=6)
    password_entry.insert(0, password)

    length_entry = tkinter.Entry(top, width=10)
    length_entry.grid(padx=(0, 20), column=1, row=6)
    length_entry.insert(0, "12")
    length_label = tkinter.Label(top, text="Length")
    length_label.grid(padx=(0, 20), column=1, row=5)
    length_entry.bind('<KeyRelease>', is_it_a_num)

    spinbox_value1 = tkinter.IntVar(value=3)
    spinbox_value2 = tkinter.IntVar(value=3)

    capital_spinbox = tkinter.Spinbox(top, from_=0, to=10, width=5, textvariable=spinbox_value1)
    capital_spinbox.grid(column=1, row=4)
    capital_label = tkinter.Label(top, text="No. of Capitals")
    capital_label.grid(column=1, row=3)

    symbol_spinbox = tkinter.Spinbox(top, from_=0, to=10, width=5, textvariable=spinbox_value2)
    symbol_spinbox.grid(column=1, row=2)
    capital_label = tkinter.Label(top, text="No. of Symbols")
    capital_label.grid(column=1, row=1)

    def generate_password():
        if is_it_a_num:
            try:
                length = int(length_entry.get())
                num_symbols = int(symbol_spinbox.get())
                num_capitals = int(capital_spinbox.get())

                if num_symbols + num_capitals > length:
                    return

                final_pass = get_char_func(num_symbols, symbols_list)
                final_pass.extend(get_char_func(num_capitals, capital_letters_list))

                remaining_length = length - num_symbols - num_capitals
                final_pass.extend(get_char_func(remaining_length, lowercase_letters_list))

                random.shuffle(final_pass)

                password = ''.join(final_pass)
                password_entry.delete(0, tkinter.END)
                password_entry.insert(0, password)
            except ValueError:
                print("Invalid input values")

    def ADD_BUTTON_INSIDE():
        website = website_name_entry.get()
        email = email_entry.get()
        password = password_entry.get()
        if len(website) < 1:
            messagebox.showerror(title="Error", message="Website cannot be empty", parent=top)
        elif len(email) < 1:
            messagebox.showerror(title="Error", message="Email cannot be empty", parent=top)
        elif len(password) < 8:
            messagebox.showerror(title="Error", message="Password is too weak (at least 8 characters)", parent=top)
        else:
            temp_list = [website, email, password]
            password_list.append(temp_list)
            write_file(password_list)
            repopulate(password_list)
            top.destroy()
            top.update()

    def cancel_button():
        top.destroy()
        top.update()

    def EDIT_BUTTON_INSIDE():
        password_list[index_of_item][0] = website_name_entry.get()
        password_list[index_of_item][1] = email_entry.get()
        password_list[index_of_item][2] = password_entry.get()
        repopulate(password_list)
        write_file(password_list)
        top.destroy()
        top.update()

    top_button_frame = tkinter.Frame(top)
    top_button_frame.grid(column=0, row=8, sticky="w", padx=5, pady=5, columnspan=3)

    generate_button = ttks.Button(top_button_frame, text="Generate", command=generate_password)
    generate_button.grid(pady=(10, 0), column=1, row=8)

    cancel_button = ttks.Button(top_button_frame, text="Cancel", bootstyle="secondary", command=cancel_button)
    cancel_button.grid(pady=(10, 0), padx=(15, 0), column=2, row=8)

    if mode != "Edit":
        add_button_inside = ttks.Button(top_button_frame, text="Add", bootstyle="success", command=ADD_BUTTON_INSIDE)
        add_button_inside.grid(pady=(10, 0), padx=(0, 15), column=0, row=8)
    else:
        edit_button_inside = ttks.Button(top_button_frame, text="Edit", bootstyle="success", command=EDIT_BUTTON_INSIDE)
        edit_button_inside.grid(pady=(10, 0), padx=(0, 15), column=0, row=8)


button_frame = tkinter.Frame(window)
button_frame.grid(column=0, row=0, sticky="w", padx=5, pady=5, columnspan=3)

add_button = ttks.Button(button_frame, text="Add", bootstyle="success", command=add_func)
add_button.pack(side="left", padx=2)

remove_button = ttks.Button(button_frame, text="Remove", bootstyle="secondary.Outline.TButton", command=delete_selected)
remove_button.pack(side="left", padx=2)

edit_button = ttks.Button(button_frame, text="Edit", bootstyle="secondary.Outline.TButton", command=edit_button_func)
edit_button.pack(side="left", padx=2)

scan_completed = False
scan_results = []
password_scan_results = []


def get_API():
    decrypted_data = login_window.decrypted_data
    api_key = ""
    for i in range(len(decrypted_data)):
        if "API =" in decrypted_data[i]:
            stringsplit = decrypted_data[i].split()
            try:
                api_key = stringsplit[2]
                return api_key
            except Exception as e:
                return api_key
    return api_key


def get_theme():
    decrypted_data = login_window.decrypted_data
    theme = "darkly"
    for i in range(len(decrypted_data)):
        if "THEME =" in decrypted_data[i]:
            stringsplit = decrypted_data[i].split()
            try:
                theme = stringsplit[2]
                return theme
            except Exception as e:
                return theme
    return theme


def update_api_buttons_state(connected):
    if connected:
        Check_accounts_button.config(bootstyle="secondary")
        Check_passwords_button.config(bootstyle="secondary")
        try:
            view_report_main_btn.config(state="normal")
        except:
            pass
    else:
        Check_accounts_button.config(bootstyle="secondary-outline")
        Check_passwords_button.config(bootstyle="secondary-outline")
        try:
            view_report_main_btn.config(state="disabled")
        except:
            pass
def on_treeview_selection_change_strength(event=None):
    selected_items = treeview.selection()
    if selected_items:
        item = selected_items[0]
        try:
            pw = treeview.item(item, "values")[2]
        except:
            pw = ""
        update_password_strength_display(pw)
    else:
        update_password_strength_display("")

def test_api_connection(api_key):
    import requests

    if not api_key or len(api_key.strip()) != 32:
        try:
            status_text.config(text="Invalid or missing API key", bootstyle="danger")
        except:
            pass
        update_api_buttons_state(False)
        return False

    headers = {
        "hibp-api-key": api_key,
        "user-agent": "Password-Manager-App"
    }

    # This is the only safe endpoint that always exists for testing
    test_email = "account-exists@hibp-integration-tests.com"
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{test_email}?truncateResponse=true"

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            try:
                status_text.config(text="Connected", bootstyle="success")
            except:
                pass
            update_api_buttons_state(True)
            return True
        elif response.status_code == 401:
            try:
                status_text.config(text="Invalid API key (401 Unauthorized)", bootstyle="danger")
            except:
                pass
        elif response.status_code == 403:
            try:
                status_text.config(text="Missing or invalid User-Agent (403 Forbidden)", bootstyle="danger")
            except:
                pass
        elif response.status_code == 404:
            try:
                status_text.config(text="Test account not found (404) — but key works", bootstyle="warning")
            except:
                pass
            update_api_buttons_state(True)
            return True
        elif response.status_code == 429:
            try:
                status_text.config(text="Rate limit exceeded (429)", bootstyle="warning")
            except:
                pass
        elif response.status_code == 503:
            try:
                status_text.config(text="Service unavailable (503)", bootstyle="danger")
            except:
                pass
        else:
            try:
                status_text.config(text=f"Unexpected HTTP {response.status_code}", bootstyle="danger")
            except:
                pass
        update_api_buttons_state(False)
        return False

    except requests.exceptions.Timeout:
        try:
            status_text.config(text="Connection timeout", bootstyle="danger")
        except:
            pass
    except requests.exceptions.RequestException:
        try:
            status_text.config(text="Connection error", bootstyle="danger")
        except:
            pass
    except Exception:
        try:
            status_text.config(text="Unexpected error", bootstyle="danger")
        except:
            pass

    update_api_buttons_state(False)
    return False



def check_account_breaches(email):
    api_key = get_API()

    if not api_key or api_key.strip() == "":
        messagebox.showerror("Error", "No API key found. Please add your API key in Settings.")
        return

    try:
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "Password-Manager-App"
        }

        from urllib.parse import quote
        encoded_email = quote(email)

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_email}?truncateResponse=false"
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            breaches = response.json()
            show_breach_results(email, breaches)
        elif response.status_code == 404:
            messagebox.showinfo("Good News!", f"No breaches found for {email}")
        elif response.status_code == 401:
            messagebox.showerror("Error", "Invalid API key. Please check your API key in Settings.")
        elif response.status_code == 429:
            retry_after = response.headers.get('retry-after', 'unknown')
            messagebox.showwarning("Rate Limited", f"Too many requests. Try again in {retry_after} seconds.")
        else:
            messagebox.showerror("Error", f"Error checking account: HTTP {response.status_code}")

    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Network error: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {str(e)}")


def show_breach_results(email, breaches):
    result_window = Toplevel()
    result_window.title(f"Breach Results for {email}")
    result_window.geometry("600x400")
    result_window.config(pady=10, padx=10)

    header_label = ttks.Label(
        result_window,
        text=f"Found {len(breaches)} breach(es) for {email}",
        font=("Arial", 12, "bold")
    )
    header_label.pack(pady=10)

    scrollbar = tkscrolled.ScrolledText(result_window, width=70, height=20, wrap=tkinter.WORD)
    scrollbar.configure(spacing3=4)

    for breach in breaches:
        scrollbar.insert(tkinter.END, f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", "separator")
        scrollbar.insert(tkinter.END, f"Breach: {breach.get('Title', 'Unknown')}\n", "title")
        scrollbar.insert(tkinter.END, f"Domain: {breach.get('Domain', 'N/A')}\n")
        scrollbar.insert(tkinter.END, f"Date: {breach.get('BreachDate', 'Unknown')}\n")
        scrollbar.insert(tkinter.END, f"Compromised Accounts: {breach.get('PwnCount', 0):,}\n")

        data_classes = breach.get('DataClasses', [])
        if data_classes:
            scrollbar.insert(tkinter.END, f"Compromised Data: {', '.join(data_classes)}\n")

        description = breach.get('Description', '')
        if description:
            from bs4 import BeautifulSoup
            clean_desc = BeautifulSoup(description, "html.parser").get_text()
            scrollbar.insert(tkinter.END, f"\nDescription: {clean_desc}\n")

        scrollbar.insert(tkinter.END, "\n")

    scrollbar.config(state="disabled")
    scrollbar.pack(pady=10, fill="both", expand=True)

    close_btn = ttks.Button(result_window, text="Close", bootstyle="secondary", command=result_window.destroy)
    close_btn.pack(pady=10)


def check_password_pwned(password):
    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {"Add-Padding": "true"}
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            hashes = response.text.splitlines()
            for hash_line in hashes:
                hash_suffix, count = hash_line.split(':')
                if hash_suffix == suffix:
                    count = int(count)
                    if count > 0:
                        return True, count
            return False, 0
        else:
            return None, 0

    except requests.exceptions.RequestException as e:
        return None, 0
    except Exception as e:
        return None, 0


def show_password_report():
    global password_scan_results

    if not password_scan_results:
        messagebox.showinfo("Info", "No vulnerable passwords to report")
        return

    report_window = Toplevel()
    report_window.title("Vulnerable Passwords Report")
    report_window.geometry("600x400")
    report_window.config(pady=10, padx=10)

    header_label = ttks.Label(
        report_window,
        text="Vulnerable Passwords Detailed Report",
        font=("Arial", 12, "bold")
    )
    header_label.pack(pady=10)

    scrollbar = tkscrolled.ScrolledText(report_window, width=70, height=20, wrap=tkinter.WORD)
    scrollbar.configure(spacing3=4)

    for website, email, count in password_scan_results:
        scrollbar.insert(tkinter.END, f"Website: {website}\n", "title")
        scrollbar.insert(tkinter.END, f"Email: {email}\n")
        scrollbar.insert(tkinter.END, f"Times exposed in breaches: {count:,}\n")
        scrollbar.insert(tkinter.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

    scrollbar.config(state="disabled")
    scrollbar.pack(pady=10, fill="both", expand=True)

    close_btn = ttks.Button(report_window, text="Close", bootstyle="secondary", command=report_window.destroy)
    close_btn.pack(pady=10)


def check_all_passwords():
    global password_scan_results
    password_scan_results = []

    if not password_list:
        messagebox.showinfo("Info", "No passwords to check")
        return

    result_window = Toplevel()
    result_window.title("Password Security Check")
    result_window.geometry("600x550")
    result_window.config(pady=10, padx=10)

    header_label = ttks.Label(
        result_window,
        text="Checking passwords against Pwned Passwords database...",
        font=("Arial", 12, "bold")
    )
    header_label.pack(pady=10)

    scrollbar = tkscrolled.ScrolledText(result_window, width=70, height=20, wrap=tkinter.WORD, font=("Arial", 10))
    scrollbar.pack(pady=10, fill="both", expand=True)

    vulnerable_count = 0

    for entry in password_list:
        website, email, password = entry[0], entry[1], entry[2]
        scrollbar.insert(tkinter.END, f"Checking {website}... ")
        scrollbar.update()

        is_pwned, count = check_password_pwned(password)

        if is_pwned:
            vulnerable_count += 1
            password_scan_results.append((website, email, count))
            scrollbar.insert(tkinter.END, f"VULNERABLE (seen {count:,} times)\n")
        elif is_pwned is False:
            scrollbar.insert(tkinter.END, "Safe\n")
        else:
            scrollbar.insert(tkinter.END, "Error checking\n")

    scrollbar.insert(tkinter.END, f"\n" + "=" * 60 + "\n")
    scrollbar.insert(tkinter.END, f"Summary: {vulnerable_count} of {len(password_list)} passwords are vulnerable\n")

    scrollbar.config(state="disabled")

    button_frame = ttks.Frame(result_window)
    button_frame.pack(pady=10)

    if vulnerable_count > 0:
        view_report_btn = ttks.Button(
            button_frame,
            text="View Report",
            bootstyle="info",
            command=show_password_report
        )
        view_report_btn.pack(side="left", padx=5)

    close_btn = ttks.Button(button_frame, text="Close", bootstyle="secondary", command=result_window.destroy)
    close_btn.pack(side="left", padx=5)


def show_detailed_report():
    global scan_results

    if not scan_results:
        messagebox.showinfo("Info", "No scan results available")
        return

    report_window = Toplevel()
    report_window.title("Detailed Breach Report")
    report_window.geometry("700x500")
    report_window.config(pady=10, padx=10)

    header_label = ttks.Label(
        report_window,
        text="Detailed Breach Report",
        font=("Arial", 14, "bold")
    )
    header_label.pack(pady=10)

    scrollbar = tkscrolled.ScrolledText(report_window, width=80, height=25, wrap=tkinter.WORD, font=("Arial", 10))
    scrollbar.pack(pady=10, fill="both", expand=True)

    for email, breaches in scan_results:
        scrollbar.insert(tkinter.END, "=" * 70 + "\n")
        scrollbar.insert(tkinter.END, f"\nEmail: {email}\n")
        scrollbar.insert(tkinter.END, f"Found in {len(breaches)} breach(es)\n\n")

        for breach in breaches:
            scrollbar.insert(tkinter.END, f"Breach: {breach.get('Title', 'Unknown')}\n")
            scrollbar.insert(tkinter.END, f"Domain: {breach.get('Domain', 'N/A')}\n")
            scrollbar.insert(tkinter.END, f"Date: {breach.get('BreachDate', 'Unknown')}\n")
            scrollbar.insert(tkinter.END, f"Compromised Accounts: {breach.get('PwnCount', 0):,}\n")

            data_classes = breach.get('DataClasses', [])
            if data_classes:
                scrollbar.insert(tkinter.END, f"Compromised Data: {', '.join(data_classes)}\n")

            description = breach.get('Description', '')
            if description:
                from bs4 import BeautifulSoup
                clean_desc = BeautifulSoup(description, "html.parser").get_text()
                scrollbar.insert(tkinter.END, f"\nDescription: {clean_desc}\n")

            scrollbar.insert(tkinter.END, "\n" + "-" * 70 + "\n\n")

    scrollbar.config(state="disabled")

    close_btn = ttks.Button(report_window, text="Close", bootstyle="secondary", command=report_window.destroy)
    close_btn.pack(pady=10)


def check_all_accounts():
    global scan_completed, scan_results

    if not password_list:
        messagebox.showinfo("Info", "No accounts to check")
        return

    api_key = get_API()
    if not api_key or api_key.strip() == "":
        messagebox.showerror("Error", "No API key found. Please add your API key in Settings.")
        return

    scan_completed = False
    scan_results = []

    unique_emails = list(set([entry[1] for entry in password_list]))

    result_window = Toplevel()
    result_window.title("Account Breach Check")
    result_window.geometry("600x550")
    result_window.config(pady=10, padx=10)

    header_label = ttks.Label(
        result_window,
        text=f"Checking {len(unique_emails)} account(s) for breaches...",
        font=("Arial", 12, "bold")
    )
    header_label.pack(pady=10)

    scrollbar = tkscrolled.ScrolledText(result_window, width=70, height=20, wrap=tkinter.WORD, font=("Arial", 10))
    scrollbar.pack(pady=10, fill="both", expand=True)

    breached_count = 0

    for email in unique_emails:
        scrollbar.insert(tkinter.END, f"Checking {email}... ")
        scrollbar.update()

        try:
            headers = {
                "hibp-api-key": api_key,
                "user-agent": "Password-Manager-App"
            }

            from urllib.parse import quote
            encoded_email = quote(email)
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_email}?truncateResponse=false"

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                breaches = response.json()
                breached_count += 1
                scan_results.append((email, breaches))
                scrollbar.insert(tkinter.END, f"Found in {len(breaches)} breach(es)\n")
            elif response.status_code == 404:
                scrollbar.insert(tkinter.END, "No breaches found\n")
            elif response.status_code == 429:
                scrollbar.insert(tkinter.END, "Rate limited\n")
                break
            else:
                scrollbar.insert(tkinter.END, f"Error (HTTP {response.status_code})\n")

            import time
            time.sleep(1.5)

        except Exception as e:
            scrollbar.insert(tkinter.END, f"Error: {str(e)}\n")

    scrollbar.insert(tkinter.END, f"\n" + "=" * 60 + "\n")
    scrollbar.insert(tkinter.END, f"Summary: {breached_count} of {len(unique_emails)} accounts found in breaches\n")

    scrollbar.config(state="disabled")

    scan_completed = True

    button_frame = ttks.Frame(result_window)
    button_frame.pack(pady=10)

    view_report_btn = ttks.Button(
        button_frame,
        text="View Report",
        bootstyle="info" if breached_count > 0 else "secondary-outline",
        command=show_detailed_report if breached_count > 0 else None
    )
    view_report_btn.pack(side="left", padx=5)

    close_btn = ttks.Button(button_frame, text="Close", bootstyle="secondary", command=result_window.destroy)
    close_btn.pack(side="left", padx=5)


def check_password_strength(password):
    common_passwords = set()
    try:
        with open('common_passwords.txt', 'r') as f:
            common_passwords = set(line.strip() for line in f)
    except:
        pass

    if password in common_passwords:
        return 0, True

    length_ok = len(password) >= 8
    digit_ok = re.search(r"\d", password) is not None
    uppercase_ok = re.search(r"[A-Z]", password) is not None
    lowercase_ok = re.search(r"[a-z]", password) is not None
    symbol_ok = re.search(r"[{0}]".format(re.escape(string.punctuation)), password) is not None

    conditions_met = sum([length_ok, digit_ok, uppercase_ok, lowercase_ok, symbol_ok])

    return conditions_met, False


def update_password_strength_display(password):
    if not password:
        strength_gauge.configure(value=0, bootstyle="secondary")
        strength_label.config(text="")
        return

    score, is_common = check_password_strength(password)

    # Convert score (0-5) to percentage (0-100) for progressbar
    percentage = (score / 5) * 100
    strength_gauge.configure(value=percentage)

    if is_common:
        strength_gauge.configure(bootstyle="danger")
        strength_label.config(text="COMMON", bootstyle="danger")
    elif score == 0:
        strength_gauge.configure(bootstyle="danger")
        strength_label.config(text="EMPTY", bootstyle="danger")
    elif score == 1:
        strength_gauge.configure(bootstyle="danger")
        strength_label.config(text="VERY WEAK", bootstyle="danger")
    elif score == 2:
        strength_gauge.configure(bootstyle="warning")
        strength_label.config(text="WEAK", bootstyle="warning")
    elif score == 3:
        strength_gauge.configure(bootstyle="warning")
        strength_label.config(text="MODERATE", bootstyle="warning")
    elif score == 4:
        strength_gauge.configure(bootstyle="info")
        strength_label.config(text="STRONG", bootstyle="info")
    elif score == 5:
        strength_gauge.configure(bootstyle="success")
        strength_label.config(text="VERY STRONG", bootstyle="success")
    else:
        strength_gauge.configure(bootstyle="secondary")
        strength_label.config(text="")



def settings_func():
    settings_page = Toplevel()
    settings_page.geometry("500x310")
    settings_page.title("Settings")
    settings_page.config(pady=10)
    settings_notebook = ttks.Notebook(settings_page)
    settings_notebook.pack(padx=10)
    api_frame = ttks.Frame(settings_notebook)
    theme_frame = ttks.Frame(settings_notebook)
    about_frame = ttks.Frame(settings_notebook)
    api_frame.configure(padding=10)
    theme_frame.configure(padding=10)

    settings_notebook.add(api_frame, text="API")
    settings_notebook.add(theme_frame, text="Theme")
    settings_notebook.add(about_frame, text="About")

    API_info = ttks.Label(api_frame,
                          text="\nEnter Your Have I Been Pwned API key here. \nYou may get one at their website: https://haveibeenpwned.com/Dashboard\n\n\n")
    API_info.pack(side="top")
    API_entry_label = ttks.Label(api_frame, text="API Key")
    API_entry_label.pack(side="left", pady=(0, 100))

    API_entry = ttks.Entry(api_frame)
    try:
        API_entry.insert(index=0, string=f"{api_key}")
    except:
        API_entry.insert(index=0, string="")
    API_entry.pack(side="left", pady=(0, 100), padx=(15, 0))

    def writeAPI():
        global api_key
        api_key = API_entry.get()
        decrypted_data = login_window.decrypted_data
        for i in range(len(decrypted_data)):
            if "API =" in decrypted_data[i]:
                decrypted_data[i] = "API = " + api_key
        login_window.write_to_file(decrypted_data)
        test_api_connection(api_key)
        try:
            settings_page.destroy()
        except:
            pass

    API_submit_button = ttks.Button(api_frame, text="Submit", command=writeAPI)
    API_submit_button.pack(side="left", pady=(0, 100), padx=(15, 0))

    theme_info = ttks.Label(theme_frame, text="\nSelect your preferred theme:\n\n")
    theme_info.pack(side="top")

    theme_var = tkinter.StringVar(value=current_theme)
    theme_combobox = ttks.Combobox(theme_frame, textvariable=theme_var, values=["darkly", "sandstone", "morph", "superhero"], state="readonly")
    theme_combobox.pack(pady=10)

    def apply_theme():
        new_theme = theme_var.get()
        decrypted_data = login_window.decrypted_data
        theme_found = False
        for i in range(len(decrypted_data)):
            if "THEME =" in decrypted_data[i]:
                decrypted_data[i] = "THEME = " + new_theme
                theme_found = True
                break
        if not theme_found:
            decrypted_data.append("THEME = " + new_theme)
        login_window.write_to_file(decrypted_data)
        try:
            ttks.Style().theme_use(new_theme)
            window.update()
        except:
            try:
                window.destroy()
            except:
                pass

    theme_apply_button = ttks.Button(theme_frame, text="Apply Theme", command=apply_theme)
    theme_apply_button.pack(pady=10)

    About_label = ttks.Label(about_frame, text="\nThis an educational/personal project made by Faisal Al-Saadi.\n"
                                               "\nIt can be found on my GitHub page here https://github.com/FaisalAlsaadi\n\n"
                                               "If someone found this project useful and would like more features \nplease do not hesitate to email me: "
                                               "Faisal.alsaadi@protonmail.com\n"
                                               "\nThank you for checking it out!")
    About_label.pack(side="top", pady=(0, 10), padx=5)


settings_button = ttks.Button(button_frame, text="Settings", bootstyle="secondary", command=settings_func)
settings_button.pack(side="right", padx=(192, 0))


def delete_placeholder(event):
    search_bar.delete(0, tkinter.END)


def return_placeholder(event):
    tree_selection = treeview.selection()
    if tree_selection:
        pass
    else:
        search_bar.insert(0, "Search")


def search_func(event):
    global password_list
    local_password_list = []
    search_string = search_bar.get()
    if search_string == "":
        repopulate(password_list)
    else:
        for lists in password_list:
            for item in lists:
                try:
                    if search_string in item:
                        local_password_list.append(lists)
                        break
                except:
                    pass
        repopulate(local_password_list)


search_bar = ttks.Entry(button_frame, style="light.TEntry")
search_bar.pack(side="left", padx=10)
search_bar.insert(0, "Search")
search_bar.bind("<FocusIn>", delete_placeholder)
search_bar.bind("<FocusOut>", return_placeholder)
search_bar.bind("<KeyRelease>", search_func)


def change_button_color(event=None):
    selected_items = treeview.selection()
    if selected_items:
        remove_button.config(bootstyle="danger")
        edit_button.config(bootstyle="info")
    else:
        remove_button.config(bootstyle="secondary-outline")
        edit_button.config(bootstyle="secondary-outline")
    on_treeview_selection_change_strength(event)


def on_treeview_click(event):
    item = treeview.identify_row(event.y)
    if not item:
        treeview.selection_remove(treeview.selection())
        change_button_color()


treeview.bind('<<TreeviewSelect>>', change_button_color)
treeview.bind('<ButtonPress-1>', on_treeview_click)


def edit_double(event):
    selected_items = treeview.selection()
    if selected_items:
        edit_button_func()


def delete_on_del(event):
    selected_items = treeview.selection()
    if selected_items:
        delete_selected()


treeview.bind("<Double-Button-1>", edit_double)
treeview.bind("<Return>", edit_double)
treeview.bind("<Delete>", delete_on_del)

API_label = ttks.Labelframe(window, text="Have I been Pawned", style='default')
API_label.grid(row=2, column=0, sticky="w", padx=20, pady=0)

global Check_accounts_button, Check_passwords_button

button_frame2 = tkinter.Frame(window)
button_frame2.grid(column=0, row=3, sticky="w", padx=5, pady=(10, 5), columnspan=3)

status_frame = ttks.Frame(API_label)
status_frame.pack(padx=10, pady=10, fill="x")

status_prefix = ttks.Label(status_frame, text="Status: ", font=("Arial", 9))
status_prefix.pack(side="left")

status_text = ttks.Label(status_frame, text="Testing...", font=("Arial", 9))
status_text.pack(side="left")
# Create a frame for the strength indicator
strength_container = ttks.Frame(window)
strength_container.grid(row=2, column=1, rowspan=2, padx=(10, 20), pady=10, sticky="n")

# Fix the width to prevent resizing
strength_container.grid_propagate(False)
strength_container.configure(width=120, height=140)  # Set fixed dimensions

# Use a Progressbar instead of Meter for better control
strength_gauge = ttks.Progressbar(
    strength_container,
    orient='vertical',
    length=100,
    value=0,
    bootstyle="secondary"
)
strength_gauge.pack(pady=5)

# Create a fixed-width label that won't cause resizing, with centered text
strength_label = ttks.Label(strength_container, text="", font=("Arial", 10), width=12, anchor="center")
strength_label.pack()





Check_accounts_button = ttks.Button(API_label, text="Check Accounts", bootstyle="secondary-outline",
                                    command=check_all_accounts)
Check_accounts_button.pack(side="left", padx=10, pady=10)

Check_passwords_button = ttks.Button(API_label, text="Check Passwords", bootstyle="secondary-outline",
                                     command=check_all_passwords)
Check_passwords_button.pack(side="left", padx=10, pady=10)



api_key = get_API()
current_theme = get_theme()
test_api_connection(api_key)

latest_dict = None


def latest_func():
    global latest_dict
    if latest_dict is None:
        x = requests.get("https://haveibeenpwned.com/api/v3/latestbreach")
        latest_dict = json.loads(x.text)
    latest_window = Toplevel(pady=10)
    latest_window.geometry("500x370")
    latest_window.title("Latest News")
    latest_window.resizable(width=False, height=False)
    print(latest_dict)

    def cutoff_text_func(text):
        iterations = len(text) // 55
        cutoff_length = 60
        offset = 0

        for i in range(1, iterations, 1):
            iteration_count = i * cutoff_length + offset
            for j in range(iteration_count, iteration_count - 10, -1):
                if text[j] == " ":
                    text = text[:j] + "\n" + text[j + 1:]
                    offset += (j - iteration_count)
                    break
        return text

    scrollbar = tkscrolled.ScrolledText(latest_window, width=60, height=20)
    scrollbar.configure(spacing3=4)
    for key in latest_dict:
        if key in ["Name", "Domain", "AddedDate", "Description", "PwnCount"]:
            if key == "Description":
                descript = latest_dict[key]
                soup = BeautifulSoup(descript, "html.parser")
                output_text = soup.get_text()

                scrollbar.insert(tkinter.END, f"{key}: {cutoff_text_func(output_text)}\n\n")
            elif key == "AddedDate":
                formatted_date = latest_dict[key].split("T")
                formatted_date[1] = formatted_date[1].replace("Z", "")
                scrollbar.insert(tkinter.END, f"Date: {formatted_date[0]} {formatted_date[1]}\n\n")
            elif key == "PwnCount":
                scrollbar.insert(tkinter.END, f"Number of affected: {int(latest_dict[key]):,}\n\n")
            else:
                scrollbar.insert(tkinter.END, f"{key}: {latest_dict[key]}\n\n")
    scrollbar.config(state="disabled")
    scrollbar.pack(side="top")

    def latest_close():
        latest_window.destroy()

    close_button = ttks.Button(latest_window, text="Close", bootstyle="secondary", command=latest_close)
    close_button.pack(side="top", padx=2, pady=(10, 0))
    window.selection_clear()


latest_button = ttks.Button(API_label, text="Latest News", bootstyle="secondary", command=latest_func)
latest_button.pack(side="left", padx=10, pady=10)

try:
    window.deiconify()
except:
    pass

window.mainloop()
