from rich.prompt import Prompt
from halo import Halo
from os import path, mkdir
from json import dump, load
from termcolor import colored
from hashlib import sha256

from .modules.encryption import DataManipulation

def main(obj: DataManipulation):
    if path.isfile('db/masterpassword.json'):
        with open('db/masterpassword.json') as jsondata:
            jfile = load(jsondata)

        stored_master_password = jfile['Master']
        master_password = Prompt.ask("Enter master password", password=True)
        if sha256(master_password.encode('utf-8')).hexdigest() == stored_master_password:
            print(colored(f"{obj.checkmark_} Thank you!", "green"))
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
            spinner = Halo(text=colored('Initializing base...', 'green'), spinner=obj.dots_, color="green")
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
        print("Master password is: " + master_password)

if __name__ == "__main__":
    obj = DataManipulation()
    main(obj)
