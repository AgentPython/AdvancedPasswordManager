from rich.prompt import Prompt, Confirm
from halo import Halo
from os import path, mkdir
from json import dump, load
from termcolor import colored
from hashlib import sha256
from sys import exit
from pyperclip import copy 

from .modules.exceptions import *
from .modules.encryption import DataManipulation
from .modules.menu import Manager

from rich.console import Console

console = Console()

def exit_program():
    print('\n')
    print(colored("❯", "red"))
    exit()

obj = DataManipulation()
def main():
    try:
        if path.isfile('db/masterpassword.json'):
            with open('db/masterpassword.json') as jsondata:
                jfile = load(jsondata)
            stored_master_password = jfile['Master']
            master_password = Prompt.ask("Enter master password", password=True)
            if sha256(master_password.encode('utf-8')).hexdigest() == stored_master_password:
                print(colored(f"{obj.checkmark_} Thank you!", "green"))
                menu = Manager(obj, "db/passwords.json", "db/masterpassword.json", master_password)
                try:
                    menu.begin()
                except UserExits:
                    exit_program()
                except PasswordFileDoesNotExist:
                    print(colored(f"{obj.x_mark} DB not found. Try adding a password {obj.x_mark}", "red"))
            else:
                print(colored(f"{obj.x_mark} Master password is incorrect, please try again!", "red"))
        else:
            try:
                mkdir('db/')
            except FileExistsError:
                pass
    
            master_password = Prompt.ask("Enter master password", password=True)
            master_password_verification = Prompt.ask("Verify your master password", password=True)

            if master_password == master_password_verification:
                console.print(f"Your master password is [bold][green]{master_password}[/green][/bold].")
                confirmation_copy = Confirm.ask("Copy master password to clipboard")
                if confirmation_copy:
                    copy(master_password)
                    console.print(f"[green]{obj.checkmark_} Copied to clipboard[/green]")

                spinner = Halo(text=colored('Initializing base...', 'green'), spinner=obj.dots_, color="green")
                spinner.start()
                hash_master = sha256(master_password.encode('utf-8')).hexdigest()
                jfile = {
                    "Master": hash_master
                }
                with open('db/masterpassword.json', 'w') as jsondata:
                    dump(jfile, jsondata, sort_keys=True, indent=4)
                spinner.stop()
                print(colored(f"{obj.checkmark_} Thank you! please restart the program", 'green'))
            else:
                print(colored(f"{obj.x_mark} Password do not match, please try again!", "red"))
    except KeyboardInterrupt:
        exit_program()

if __name__ == "__main__":
    main()
