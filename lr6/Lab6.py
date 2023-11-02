import tkinter as tk
import tkinter.messagebox as messagebox
from tkinter import simpledialog
import os
import hashlib
from cryptography.fernet import Fernet
import base64
import random
from cryptography.fernet import InvalidToken
import winreg
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA
import pyautogui
import wmi
import subprocess
import psutil
import ctypes

class User:
    def __init__(self, username, password, is_locked=False, password_constraints=True, code_phrase=""):
        self.username = username
        self.password = password
        self.is_locked = is_locked
        self.password_constraints = password_constraints


login_attempts = 0
root = None
username_entry = None
password_entry = None
code_phrase_entry = None
confirm_entry = None
code_window = None

def generate_and_save_salt(code_phrase):
    random.seed(code_phrase)
    salt = bytes(random.getrandbits(8) for i in range(16))
    return salt


def hash_code_phrase(code_phrase):
    md4 = hashlib.new('md5')
    md4.update(code_phrase.encode('utf-8'))
    return md4.hexdigest()


def create_admin_user_file_if_not_exists(code_phrase):
    salt = generate_and_save_salt(code_phrase)
    if not os.path.exists("users.bin"):
        admin = User("ADMIN", "", False, True)
        admin_data = f"{admin.username},{hash_code_phrase(admin.password)},{admin.is_locked},{admin.password_constraints}\n"
        key = hashlib.pbkdf2_hmac("md5", code_phrase.encode('utf-8'), salt, 100, 32)
        key_base64 = base64.urlsafe_b64encode(key)
        cipher_suite = Fernet(key_base64)
        encrypted_data = cipher_suite.encrypt(admin_data.encode('utf-8'))

        with open("users.bin", "wb") as file:
            file.write(encrypted_data)


def read_users_from_file(code_phrase):
    users = []
    with open("users.bin", "rb") as file:
        encrypted_data = file.read()

        salt = generate_and_save_salt(code_phrase)
        key = hashlib.pbkdf2_hmac("md5", code_phrase.encode('utf-8'), salt, 100, 32)
        key_base64 = base64.urlsafe_b64encode(key)
        cipher_suite = Fernet(key_base64)
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode('utf-8')
        lines = decrypted_data.strip().split('\n')

        for line in lines:
            parts = line.strip().split(",")
            if len(parts) == 4:
                username, password, is_locked, password_constraints = parts
                user = User(username, password, is_locked == "True", password_constraints == "True")
                users.append(user)
            else:
                admin = User("ADMIN", "", False, True)
                users.append(admin)
    return users


def decrypt_users_to_temp_file(code_phrase):
    users = read_users_from_file(code_phrase)

    with open("users_decrypted.bin", "wb") as decrypted_file:
        for user in users:
            user_info = f"{user.username},{user.password},{user.is_locked},{user.password_constraints}\n"
            user_info_bytes = user_info.encode('utf-8')
            decrypted_file.write(user_info_bytes)


def encrypt_and_save_users(users, code_phrase):
    data_to_encrypt = ""
    for user in users:
        data_to_encrypt += f"{user.username},{user.password},{user.is_locked},{user.password_constraints}\n"

    salt = generate_and_save_salt(code_phrase)
    key = hashlib.pbkdf2_hmac("md5", code_phrase.encode('utf-8'), salt, 100, 32)
    key_base64 = base64.urlsafe_b64encode(key)
    cipher_suite = Fernet(key_base64)
    encrypted_data = cipher_suite.encrypt(data_to_encrypt.encode('utf-8'))

    with open("users.bin", "wb") as file:
        file.write(encrypted_data)

    if os.path.exists("users_decrypted.bin"):
        os.remove("users_decrypted.bin")


def read_users_from_temp_file():
    users = []
    with open("users_decrypted.bin", "rb") as file:
        lines = file.readlines()
        for line in lines:
            parts = line.strip().decode('utf-8').split(",")
            if len(parts) == 4:
                username, password, is_locked, password_constraints = parts
                user = User(username, password, is_locked == "True", password_constraints == "True")
                users.append(user)
    return users


def save_users_to_temp_file(users):
    with open("users_decrypted.bin", "wb") as file:
        for user in users:
            user_info = f"{user.username},{user.password},{user.is_locked},{user.password_constraints}\n"
            user_info_bytes = user_info.encode('utf-8')
            file.write(user_info_bytes)


def save_users_to_file(users, code_phrase):
    data_to_encrypt = ""
    for user in users:
        data_to_encrypt += f"{user.username},{user.password},{user.is_locked},{user.password_constraints}\n"

    salt = generate_and_save_salt(code_phrase)
    key = hashlib.pbkdf2_hmac("md5", code_phrase.encode('utf-8'), salt, 100, 32)
    key_base64 = base64.urlsafe_b64encode(key)
    cipher_suite = Fernet(key_base64)
    encrypted_data = cipher_suite.encrypt(data_to_encrypt.encode('utf-8'))

    with open("users.bin", "wb") as file:
        file.write(encrypted_data)


def exit_program(root, code_phrase):
    users = read_users_from_temp_file()
    encrypt_and_save_users(users, code_phrase)
    root.destroy()


def exit_start(root):
    if os.path.exists("users_decrypted.bin"):
        os.remove("users_decrypted.bin")
    root.destroy()


def pass_restrictions(password):
    for i in range(0, len(password) - 1):
        if password[i] == password[i + 1]:
            return False
    return True


def login(code_phrase):
    global username_entry
    global password_entry
    global login_attempts
    username = username_entry.get()
    password = password_entry.get()

    users = read_users_from_temp_file()
    found_user = None

    for user in users:
        if user.username == username:
            found_user = user
            break

    if found_user:
        if found_user.is_locked:
            messagebox.showerror("Ошибка", "Учетная запись заблокирована.")
        elif hash_code_phrase(password) == found_user.password and found_user.username == 'ADMIN':
            open_admin_window(code_phrase)
            password_entry.delete(0, tk.END)
            login_attempts = 0
        elif hash_code_phrase(password) == found_user.password and found_user.username != 'ADMIN':
            open_user_window(code_phrase)
            password_entry.delete(0, tk.END)
            login_attempts = 0
        else:
            login_attempts += 1
            if login_attempts == 1:
                messagebox.showerror("Ошибка", f"Неверный пароль. Осталось {3 - login_attempts} попытки")
            elif login_attempts == 2:
                messagebox.showerror("Ошибка", f"Неверный пароль. Осталось {3 - login_attempts} попытка")
            else:
                messagebox.showerror("Ошибка", f"Неверный пароль. Осталось {3 - login_attempts} попыток")
            if login_attempts >= 3:
                messagebox.showerror("Ошибка", "Превышено количество попыток входа.")
                exit_program(root, code_phrase)
    else:
        messagebox.showerror("Ошибка", "Неверный логин.")

    save_users_to_temp_file(users)


def lock_user():
    username_to_lock = simpledialog.askstring("Изменение состояния блокировки пользователя",
                                              "Введите имя пользователя:")

    if not username_to_lock:
        return

    users = read_users_from_temp_file()

    for user in users:
        if user.username == username_to_lock:
            user.is_locked = not user.is_locked
            save_users_to_temp_file(users)
            if user.is_locked:
                messagebox.showinfo("Успех", f"Пользователь {username_to_lock} успешно заблокирован.")
            else:
                messagebox.showinfo("Успех", f"Пользователь {username_to_lock} успешно разблокирован.")
            return

    messagebox.showerror("Ошибка", f"Пользователь {username_to_lock} не найден.")


def toggle_password_constraints():
    users = read_users_from_temp_file()

    for user in users:
        user.password_constraints = not user.password_constraints

    save_users_to_temp_file(users)
    messagebox.showinfo("Успех", "Ограничения на пароли изменены.")


def toggle_password_constraints_for_user():
    user_to_toggle = simpledialog.askstring("Изменение ограничений на пароль", "Введите имя пользователя:")

    if not user_to_toggle:
        return

    users = read_users_from_temp_file()

    for user in users:
        if user.username == user_to_toggle:
            user.password_constraints = not user.password_constraints
            save_users_to_temp_file(users)
            if user.password_constraints:
                messagebox.showinfo("Успех",
                                    f"Ограничения на пароль для пользователя {user_to_toggle} успешно включены.")
            else:
                messagebox.showinfo("Успех",
                                    f"Ограничения на пароль для пользователя {user_to_toggle} успешно выключены.")
            return

    messagebox.showerror("Ошибка", f"Пользователь {user_to_toggle} не найден.")


def change_admin_password():
    users = read_users_from_temp_file()

    for user in users:
        if user.username == "ADMIN":
            while True:
                old_password = simpledialog.askstring("Смена пароля", "Введите старый пароль:", show='*')
                if old_password is None:
                    return

                if hash_code_phrase(old_password) == user.password:
                    while True:
                        new_password = simpledialog.askstring("Смена пароля", "Введите новый пароль:", show='*')
                        if new_password is None:
                            return

                        confirm_password = simpledialog.askstring("Смена пароля", "Повторите новый пароль:", show='*')

                        if new_password != confirm_password:
                            messagebox.showerror("Ошибка", "Пароли не совпадают. Попробуйте снова.")
                            continue

                        if not pass_restrictions(new_password):
                            messagebox.showerror("Ошибка",
                                                 "Новый пароль не соответствует ограничениям. Попробуйте снова.")
                            messagebox.showerror("Ограничения", "Отсутствие подряд расположенных одинаковых символов.")
                            continue

                        user.password = hash_code_phrase(new_password)
                        save_users_to_temp_file(users)
                        messagebox.showinfo("Успех", "Пароль успешно изменен.")
                        return
                else:
                    messagebox.showerror("Ошибка", "Старый пароль неверен. Попробуйте снова.")
                    continue


def change_user_password():
    current_username = username_entry.get()

    if not current_username:
        messagebox.showerror("Ошибка", "Необходимо войти в систему, чтобы изменить пароль.")
        return

    users = read_users_from_temp_file()

    for user in users:
        if user.username == current_username:
            while True:
                old_password = simpledialog.askstring("Смена пароля", "Введите старый пароль:", show='*')
                if old_password is None:
                    return

                if user.password == hash_code_phrase(old_password):
                    while True:
                        new_password = simpledialog.askstring("Смена пароля", "Введите новый пароль:", show='*')
                        if new_password is None:
                            return

                        confirm_password = simpledialog.askstring("Смена пароля", "Повторите новый пароль:", show='*')

                        if new_password != confirm_password:
                            messagebox.showerror("Ошибка", "Пароли не совпадают. Попробуйте снова.")
                            continue

                        if not pass_restrictions(new_password):
                            messagebox.showerror("Ошибка",
                                                 "Новый пароль не соответствует ограничениям. Попробуйте снова.")
                            messagebox.showerror("Ограничения", "Отсутствие подряд расположенных одинаковых символов.")
                            continue

                        user.password = hash_code_phrase(new_password)
                        save_users_to_temp_file(users)
                        messagebox.showinfo("Успех", f"Пароль пользователя {current_username} успешно изменен.")
                        return
                else:
                    messagebox.showerror("Ошибка", "Неверный старый пароль. Попробуйте снова.")
            return

    messagebox.showerror("Ошибка", f"Пользователь {current_username} не найден.")


def view_users():
    users = read_users_from_temp_file()

    users_list_window = tk.Toplevel(root)
    users_list_window.title("Список пользователей")

    text_widget = tk.Text(users_list_window, wrap=tk.WORD)
    text_widget.pack(expand=True, fill=tk.BOTH)

    for user in users:
        info = f"Имя: {user.username}, Пароль: {user.password}, Заблокирован: {user.is_locked}, Ограничения на пароль: {user.password_constraints}\n\n"
        text_widget.insert(tk.END, info)

    text_widget.config(state=tk.DISABLED)

    users_list_window.update()
    users_list_window.geometry(f"{text_widget.winfo_width()}x{text_widget.winfo_height()}")


def add_user():
    new_username = simpledialog.askstring("Добавление пользователя", "Введите имя нового пользователя:")

    if not new_username:
        return

    users = read_users_from_temp_file()

    for user in users:
        if user.username == new_username:
            messagebox.showerror("Ошибка", "Пользователь с таким именем уже существует.")
            return

    new_user = User(new_username, hash_code_phrase(""), False, True)
    users.append(new_user)
    save_users_to_temp_file(users)
    messagebox.showinfo("Успех", f"Пользователь {new_username} успешно добавлен.")


admin_window = None
user_window = None


def open_admin_window(code_phrase):
    global admin_window
    if admin_window:
        admin_window.destroy()
    if user_window:
        user_window.destroy()
    admin_window = tk.Toplevel(root)
    admin_window.title("Режим администратора")
    admin_window.geometry("1600x200")

    admin_menu_bar = tk.Menu(admin_window)
    admin_window.config(menu=admin_menu_bar)

    admin_help_menu = tk.Menu(admin_menu_bar, tearoff=0)
    admin_menu_bar.add_cascade(label="Справка", menu=admin_help_menu)
    admin_help_menu.add_command(label="О программе", command=show_about_info)

    admin_program_menu = tk.Menu(admin_menu_bar, tearoff=0)
    admin_menu_bar.add_cascade(label="Программа", menu=admin_program_menu)
    admin_program_menu.add_command(label="Выход", command=lambda: exit_program(root, code_phrase))

    admin_operations_frame = tk.Frame(admin_window)
    admin_operations_frame.pack()

    change_password_button = tk.Button(admin_operations_frame, text="Сменить пароль", command=change_admin_password)
    change_password_button.pack(side='left')

    users = read_users_from_temp_file()
    admin_user = None

    for user in users:
        if user.username == "ADMIN":
            admin_user = user
            break

    if user.password != hash_code_phrase(''):
        view_users_button = tk.Button(admin_operations_frame, text="Просмотр пользователей", command=view_users)
        view_users_button.pack(side='left')

        add_user_button = tk.Button(admin_operations_frame, text="Добавить пользователя", command=add_user)
        add_user_button.pack(side='left')

        lock_user_button = tk.Button(admin_operations_frame, text="Заблокировать/разблокировать пользователя",
                                     command=lock_user)
        lock_user_button.pack(side='left')

        toggle_password_constraints_button = tk.Button(admin_operations_frame,
                                                       text="Включить/отключить ограничения на пароли",
                                                       command=toggle_password_constraints_for_user)
        toggle_password_constraints_button.pack(side='left')

    exit_button = tk.Button(admin_operations_frame, text="Завершение работы с программой",
                            command=lambda: exit_program(root, code_phrase))
    exit_button.pack(side='left')


def open_user_window(code_phrase):
    global user_window
    global admin_window
    if user_window:
        user_window.destroy()
    if admin_window:
        admin_window.destroy()
    user_window = tk.Toplevel(root)
    user_window.title("Режим пользователя")
    user_window.geometry("1600x200")

    user_menu_bar = tk.Menu(user_window)
    user_window.config(menu=user_menu_bar)

    user_help_menu = tk.Menu(user_menu_bar, tearoff=0)
    user_menu_bar.add_cascade(label="Справка", menu=user_help_menu)
    user_help_menu.add_command(label="О программе", command=show_about_info)

    user_program_menu = tk.Menu(user_menu_bar, tearoff=0)
    user_menu_bar.add_cascade(label="Программа", menu=user_program_menu)
    user_program_menu.add_command(label="Выход", command=lambda: exit_program(root, code_phrase))

    user_operations_frame = tk.Frame(user_window)
    user_operations_frame.pack()

    change_password_button = tk.Button(user_operations_frame, text="Сменить пароль", command=change_user_password)
    change_password_button.pack(side='left')

    view_users_button = tk.Button(user_operations_frame, text="Просмотр пользователей", command=view_users)
    view_users_button.pack(side='left')
    view_users_button.config(state='disabled')

    add_user_button = tk.Button(user_operations_frame, text="Добавить пользователя", command=add_user)
    add_user_button.pack(side='left')
    add_user_button.config(state='disabled')

    lock_user_button = tk.Button(user_operations_frame, text="Заблокировать пользователя", command=lock_user)
    lock_user_button.pack(side='left')
    lock_user_button.config(state='disabled')

    toggle_password_constraints_button = tk.Button(user_operations_frame,
                                                   text="Включить/отключить ограничения на пароли",
                                                   command=toggle_password_constraints_for_user)
    toggle_password_constraints_button.pack(side='left')
    toggle_password_constraints_button.config(state='disabled')

    exit_button = tk.Button(user_operations_frame, text="Завершение работы с программой",
                            command=lambda: exit_program(root, code_phrase))
    exit_button.pack(side='left')


def show_about_info():
    about_info = """
    Автор: Алибеков Аслан А-13а-20
    Вариант: № 23
    Индивидуальное задание: Блочный тип симметричного шифрования в режиме сцепления блоков.
    """
    tk.messagebox.showinfo("О программе", about_info)


def create_main_window(code_phrase):
    global username_entry
    global password_entry
    global root
    root = tk.Tk()
    root.eval('tk::PlaceWindow . center')
    root.title("лабораторная работа №6")

    root.geometry("300x150")
    username_label = tk.Label(root, text="Логин:", font=("Helvetica", 10))
    username_label.grid(row=0, column=0)

    username_entry = tk.Entry(root, font=("Helvetica", 10))
    username_entry.grid(row=0, column=1, pady=5)

    password_label = tk.Label(root, text="Пароль:", font=("Helvetica", 10))
    password_label.grid(row=1, column=0)

    password_entry = tk.Entry(root, show="*", font=("Helvetica", 10))
    password_entry.grid(row=1, column=1, pady=5)

    button_frame = tk.Frame(root)
    button_frame.grid(row=2, column=0, columnspan=2)

    login_button = tk.Button(button_frame, text="Войти", command=lambda: login(code_phrase), bg='green', fg='black',
                             width=10)
    login_button.pack(side="left", padx=5)

    exit_button = tk.Button(button_frame, text="Выход", command=lambda: exit_program(root, code_phrase), bg='red',
                            fg='black', width=10)
    exit_button.pack(side="left", padx=5)

    menu_bar = tk.Menu(root)
    root.config(menu=menu_bar)

    program_menu = tk.Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="Программа", menu=program_menu)
    program_menu.add_command(label="Выход", command=lambda: exit_program(root, code_phrase))

    help_menu = tk.Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="Справка", menu=help_menu)
    help_menu.add_command(label="О программе", command=show_about_info)

    root.mainloop()


def check_code_phrase():
    global code_phrase_entry, code_window
    code_phrase = code_phrase_entry.get()

    try:
        decrypt_users_to_temp_file(code_phrase)
        users = read_users_from_temp_file()

        admin_found = any(user.username == "ADMIN" for user in users)

        if admin_found:
            code_window.destroy()
            create_main_window(code_phrase)
        else:
            messagebox.showerror("Ошибка", "Неверная кодовая фраза.")
            exit_start(code_window)
    except InvalidToken:
        messagebox.showerror("Ошибка", "Неверная кодовая фраза.")
        exit_start(code_window)


def install_code_phrase():
    global code_phrase_entry, confirm_entry, code_window
    code_phrase = code_phrase_entry.get()
    confirm_phrase = confirm_entry.get()
    if confirm_phrase == code_phrase:
        create_admin_user_file_if_not_exists(code_phrase)
        decrypt_users_to_temp_file(code_phrase)
        code_window.destroy()
        create_main_window(code_phrase)
    else:
        messagebox.showerror("Ошибка", "Кодовые фразы не совпадают. Попробуйте снова.")

def start_program():
    global code_phrase_entry, confirm_entry, code_window
    code_window = tk.Tk()
    code_window.eval('tk::PlaceWindow . center')
    code_window.title("Кодовая фраза")
    code_window.geometry("350x150")

    if os.path.exists("users.bin"):
        code_phrase_label = tk.Label(code_window, text="Кодовая фраза:", font=("Helvetica", 10))
        code_phrase_label.grid(row=0, column=0)

        code_phrase_entry = tk.Entry(code_window, show="*", font=("Helvetica", 10))
        code_phrase_entry.grid(row=0, column=1, pady=5)

        button_frame = tk.Frame(code_window)
        button_frame.grid(row=2, column=0, columnspan=2)

        login_button = tk.Button(button_frame, text="Проверить", command=lambda: check_code_phrase(), bg='green',
                             fg='black', width=10)
        login_button.pack(side="left", padx=5)

        exit_button = tk.Button(button_frame, text="Выход", command=lambda: exit_start(code_window), bg='red', fg='black',
                            width=10)
        exit_button.pack(side="left", padx=5)

        menu_bar = tk.Menu(code_window)
        code_window.config(menu=menu_bar)

        program_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Программа", menu=program_menu)
        program_menu.add_command(label="Выход", command=lambda: exit_start(code_window))

        help_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Справка", menu=help_menu)
        help_menu.add_command(label="О программе", command=show_about_info)
    else:
        code_phrase_label = tk.Label(code_window, text="Кодовая фраза:", font=("Helvetica", 10))
        code_phrase_label.grid(row=0, column=0)

        code_phrase_entry = tk.Entry(code_window, show="*", font=("Helvetica", 10))
        code_phrase_entry.grid(row=0, column=1, pady=5)

        confirm_label = tk.Label(code_window, text="Подтверждение:", font=("Helvetica", 10))
        confirm_label.grid(row=1, column=0)

        confirm_entry = tk.Entry(code_window, show="*", font=("Helvetica", 10))
        confirm_entry.grid(row=1, column=1, pady=5)

        button_frame = tk.Frame(code_window)
        button_frame.grid(row=2, column=0, columnspan=2)

        login_button = tk.Button(button_frame, text="Сохранить", command=install_code_phrase, bg='green',
                             fg='black', width=10)
        login_button.pack(side="left", padx=5)

        exit_button = tk.Button(button_frame, text="Выход", command=lambda: exit_start(code_window), bg='red', fg='black',
                            width=10)
        exit_button.pack(side="left", padx=5)

        menu_bar = tk.Menu(code_window)
        code_window.config(menu=menu_bar)

        program_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Программа", menu=program_menu)
        program_menu.add_command(label="Выход", command=lambda: exit_start(code_window))

        help_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Справка", menu=help_menu)
        help_menu.add_command(label="О программе", command=show_about_info)
    code_window.mainloop()

def get_disk_serial_number(install_dir):
    drive_letter = install_dir[:2]
    try:
        output = subprocess.check_output(f'wmic logicaldisk where "DeviceID=\'{drive_letter}\'" get VolumeSerialNumber')
        serial_number = output.decode().split('\n')[1].strip()
        return serial_number
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при получении серийного номера: {e}")
        return None

def get_keyboard_info():
    keyboard_type = ctypes.windll.user32.GetKeyboardType(1)
    keyboard_subtype = ctypes.windll.user32.GetKeyboardType(2)
    return keyboard_type, keyboard_subtype

def get_info_computer():
    install_dir = os.path.dirname(__file__)
    name_user = os.environ.get('USERNAME')
    name_computer = os.environ["COMPUTERNAME"]
    path_oc_windows = os.environ['WINDIR']
    path_system_file = os.path.join(path_oc_windows, 'System32')
    keyboard_type, keyboard_subtype = get_keyboard_info()
    height_window = pyautogui.size()[1]
    disk_device = [drive.device for drive in psutil.disk_partitions()]
    serial_number_disk = get_disk_serial_number(install_dir)

    info_computer = f"Имя пользователя: {name_user}\n"
    info_computer += f"Имя компьютера: {name_computer}\n"
    info_computer += f"Путь к папке с ОС Windows: {path_oc_windows}\n"
    info_computer += f"Путь к папке с системными файлами ОС Windows: {path_system_file}\n"
    info_computer += f"Тип клавиатуры: {keyboard_type}\n"
    info_computer += f"Подтип клавиатуры: {keyboard_subtype}\n"
    info_computer += f"Высота экрана: {height_window}\n"
    info_computer += "Дисковые устройства:\n"
    info_computer += "\n".join(disk_device)
    info_computer += f"\nСерийный номер диска, на который установленна программа: {serial_number_disk}\n"

    my_file = open("Info.txt", "w+")
    my_file.write(info_computer)
    my_file.close()

    return info_computer

def verify_signature():
    student_name = name_entry.get()
    try:
        registry_key = winreg.HKEY_CURRENT_USER
        registry_subkey = f'Software\\{student_name}'

        # Попытка открыть ключ реестра и получить данные подписи и открытого ключа
        key_handle = winreg.OpenKey(registry_key, registry_subkey, 0, winreg.KEY_READ)
        signature = winreg.QueryValueEx(key_handle, 'Signature')[0]
        public_key = RSA.import_key(winreg.QueryValueEx(key_handle, 'PublicKey')[0])
        winreg.CloseKey(key_handle)

        info_computer = get_info_computer()

        h = SHA.new(info_computer.encode('utf-8'))

        # Попытка проверить подпись с помощью открытого ключа
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            messagebox.showinfo("Успех", "ЭЦП верифицирована успешно.")
            exit_start(reestr_window)
            start_program()
        except (ValueError, TypeError):
            messagebox.showerror("Ошибка", "Неудачная проверка ЭЦП. Программа завершена.")
            exit_start(reestr_window)
    except FileNotFoundError:
        messagebox.showerror("Ошибка", "Не найден раздел реестра. Программа завершена.")
        exit_start(reestr_window)
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка при проверке ЭЦП: {str(e)}")
        exit_start(reestr_window)


reestr_window = tk.Tk()
reestr_window.eval('tk::PlaceWindow . center')
reestr_window.title("Ввод имени раздела реестра")
reestr_window.geometry("380x80")

name_label = tk.Label(reestr_window, text="Имя раздела реестра:", font=("Helvetica", 10))
name_label.grid(row=0, column=0)

name_entry = tk.Entry(reestr_window, show="*", font=("Helvetica", 10))
name_entry.grid(row=0, column=1, pady=5)

button_frame_1 = tk.Frame(reestr_window)
button_frame_1.grid(row=2, column=0, columnspan=2)

ok_button = tk.Button(button_frame_1, text="Ок", command=verify_signature, bg='green',
                     fg='black', width=10)
ok_button.pack(side="left", padx=5)

exit_button = tk.Button(button_frame_1, text="Отмена", command=lambda: exit_start(reestr_window), bg='red', fg='black',
                        width=10)
exit_button.pack(side="left", padx=5)

reestr_window.mainloop()