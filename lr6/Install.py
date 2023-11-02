import tkinter as tk
import winreg
from tkinter import filedialog, messagebox
import os
import subprocess
import psutil
import ctypes
import pyautogui
import wmi
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA


def create_and_write_signature_to_registry(info_computer, student_name):
    try:
        registry_key = winreg.HKEY_CURRENT_USER
        registry_subkey = 'Software\\' + student_name

        # Проверяем, существует ли подключ реестра, и создаем его, если он отсутствует
        try:
            key_handle = winreg.OpenKey(registry_key, registry_subkey, 0, winreg.KEY_WRITE)
        except FileNotFoundError:
            key_handle = winreg.CreateKey(registry_key, registry_subkey)

        key = RSA.generate(1024)
        h = SHA.new(info_computer.encode('utf-8'))
        signature = pkcs1_15.new(key).sign(h)

        # Запись подписи и открытого ключа в реестр
        winreg.SetValueEx(key_handle, 'Signature', 0, winreg.REG_BINARY, signature)
        winreg.SetValueEx(key_handle, 'PublicKey', 0, winreg.REG_BINARY, key.export_key())
        winreg.CloseKey(key_handle)

        messagebox.showinfo("Успех", "ЭЦП успешно создана и записана в реестр Windows.")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка при создании ЭЦП: {str(e)}")



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
    install_dir = entry_install_dir.get()
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
    return info_computer


def convert_py_to_exe_move_dir():
    py_file = 'C:\\Users\\ASLAN\\Desktop\\Защита данных\\lr6\\Lab6.py'
    exe_file = os.path.splitext(os.path.basename(py_file))[0] + '.exe'
    install_dir = entry_install_dir.get()

    try:
        if not os.path.isfile(py_file):
            messagebox.showerror("Ошибка", "Указанный .py файл не существует.")
            return

        if not os.path.exists(install_dir):
            messagebox.showerror("Ошибка", "Указанная директория для установки не существует.")
            return

        subprocess.run(
            ['C:\\Users\\ASLAN\\Desktop\\Защита данных\\lr6\\Location\\Scripts\\pyinstaller.exe', '--onefile',
             '--noconsole', py_file], capture_output=True, shell=True, check=True)
        os.rename(os.path.join('dist', exe_file), os.path.join(install_dir, entry_name_file.get() + '.exe'))
        messagebox.showinfo("Успех", "Файл успешно конвертирован и перенесен.")
    except subprocess.CalledProcessError as e:
        print(f"Ошибка команды {e.cmd}!")
    except FileNotFoundError:
        messagebox.showerror("Ошибка", "Указанный .py файл не найден.")
    except PermissionError:
        messagebox.showerror("Ошибка", "У вас нет прав на запись в указанной директории.")
    info_computer = get_info_computer()
    student_name = entry_student_name.get()
    create_and_write_signature_to_registry(info_computer, student_name)


def choose_install_dir():
    directory = filedialog.askdirectory()
    if directory:
        entry_install_dir.delete(0, tk.END)
        entry_install_dir.insert(0, directory)
        check_install_button_state()


def check_install_button_state():
    install_dir = entry_install_dir.get()
    student_name = entry_student_name.get()
    name_file = entry_name_file.get()
    if install_dir and student_name and name_file:
        install_button.config(state=tk.NORMAL)
    else:
        install_button.config(state=tk.DISABLED)


def show_about_info():
    messagebox.showinfo("О программе", "Автор: Алибеков Аслан А-13а-20\nВерсия: 1.0")


def exit_program():
    app.destroy()


app = tk.Tk()
app.title("Инсталлятор")

screen_width = app.winfo_screenwidth()
screen_height = app.winfo_screenheight()

window_width = 650
window_height = 150

x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2

app.geometry(f"{window_width}x{window_height}+{x}+{y}")

label_install_dir = tk.Label(app, text="Выберите папку для установки:")
label_install_dir.grid(row=0, column=0, sticky="w")
entry_install_dir = tk.Entry(app, width=40)
entry_install_dir.grid(row=0, column=1, columnspan=2, sticky="w")
browse_button = tk.Button(app, text="Обзор", command=choose_install_dir)
browse_button.grid(row=0, column=3, sticky="w")

label_student_name = tk.Label(app, text="Имя раздела реестра:")
label_student_name.grid(row=1, column=0, sticky="w")
entry_student_name = tk.Entry(app, width=40)
entry_student_name.grid(row=1, column=1, columnspan=2, sticky="w")

label_name_file = tk.Label(app, text='Имя программы')
label_name_file.grid(row=2, column=0, sticky="w")
entry_name_file = tk.Entry(app, width=40)
entry_name_file.grid(row=2, column=1, columnspan=2, sticky="w")

install_button = tk.Button(app, text="Установить", state=tk.DISABLED, command=convert_py_to_exe_move_dir)
install_button.grid(row=3, column=1, sticky="e")

close_button = tk.Button(app, text="Закрыть", command=exit_program)
close_button.grid(row=3, column=2, sticky="w")

entry_install_dir.bind("<KeyRelease>", lambda event: check_install_button_state())
entry_student_name.bind("<KeyRelease>", lambda event: check_install_button_state())
entry_name_file.bind("<KeyRelease>", lambda event: check_install_button_state())

menubar = tk.Menu(app)
app.config(menu=menubar)
help_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="О программе", menu=help_menu)
help_menu.add_command(label="Справка", command=show_about_info)
help_menu.add_command(label="Завершить программу", command=exit_program)

app.mainloop()
