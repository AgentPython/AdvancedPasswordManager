import string

from halo import Halo
from termcolor import colored
from os import path, remove
from json import load, dump
from Crypto.Cipher import AES
from .exceptions import *
from rich.prompt import Prompt
from random import choice
from halo import Halo

class DataManipulation:
    def __init__(self):
        self.dots_ = {"interval": 80, "frames": ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]}
        self.checkmark_ = "\u2713"
        self.x_mark = "\u2717"
        self.specialChar_ = "!@#$%^&*()-_"

    def __save_password(self, filename, data, nonce, website):
        """Saves password to Database

        Arguments:
            filename {str} -- DB to save to
            data {str} -- Password that will be saved
            nonce {hexadecimal} -- Converted from byte type to hexadecimal as byte type is not supported in JSON
            website {str} -- Name of the website for the given password
        """

        spinner = Halo(text=colored("Saving", "green"), spinner=self.dots_, color="green")
        spinner.start()
        if path.isfile(filename):
            try:
                with open(filename, 'r') as jsondata:
                    jfile = load(jsondata)
                jfile[website]["nonce"] = nonce
                jfile[website]["password"] = data
                with open(filename, 'w') as jsondata:
                    dump(jfile, jsondata, sort_keys=True, indent=4)
            except KeyError:
                with open(filename, 'r') as jsondata:
                    jfile = load(jsondata)
                jfile[website] = {}
                jfile[website]["nonce"] = nonce
                jfile[website]["password"] = data
                with open(filename, 'w') as jsondata:
                    dump(jfile, jsondata, sort_keys=True, indent=4)
        else:
            jfile = {website: {}}
            jfile[website]["nonce"] = nonce
            jfile[website]["password"] = data
            with open(filename, 'w') as jsondata:
                dump(jfile, jsondata, sort_keys=True, indent=4)
        spinner.stop()
        print(colored(f"{self.checkmark_} Saved successfully. Thank you!", "green"))

    def encrypt_data(self, filename, data, master_pass, website):
        """Encrypts the password and saves it to the DB

        Arguments:
            filename {str} -- DB to save to
            data {str} -- Password that will be saved
            master_pass {str} -- Master password to encrypt the password
            website {str} -- Name of the website for the given password
        """

        concatenated_password = master_pass + "================"
        key = concatenated_password[:16].encode('utf-8')
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce.hex()
        data_to_encrypt = data.encode('utf-8')
        encrypted_data = cipher.encrypt(data_to_encrypt).hex()
        self.__save_password(filename, encrypted_data, nonce, website)

    def decrypt_all_data(self, master_pass, filename):

        plaintext_passwords = []
        if path.isfile(filename):
            try:
                with open(filename, 'r') as jsondata:
                    jfile = load(jsondata)
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist

        formatted_master_pass = master_pass + "================" 
        master_pass_encoded = formatted_master_pass[:16].encode('utf-8')
        for website, encrypted in jfile.items():
            nonce = bytes.fromhex(encrypted['nonce'])
            password = bytes.fromhex(encrypted['password'])
            cipher = AES.new(master_pass_encoded, AES.MODE_EAX, nonce=nonce)
            plaintext_password = cipher.decrypt(password).decode('utf-8')
            plaintext_passwords.append({ "Website": website, "Password": plaintext_password })

        return plaintext_passwords


    def decrypt_data(self, master_pass, website, filename):
        """Decrypts the password and prints it to the screen

        Arguments:
            master_pass {str} -- Master password to decrypt the password
            website {str} -- Name of the website for the given password
            filename {str} -- DB to save to
        """

        if path.isfile(filename):
            try:
                with open(filename, 'r') as jsondata:
                    jfile = load(jsondata)
                nonce = bytes.fromhex(jfile[website]["nonce"])
                password = bytes.fromhex(jfile[website]["password"])
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist

        formatted_master_pass = master_pass + "================"
        master_pass_encoded = formatted_master_pass[:16].encode('utf-8')
        cipher = AES.new(master_pass_encoded, AES.MODE_EAX, nonce=nonce)
        plaintext_password = cipher.decrypt(password).decode('utf-8')

        return plaintext_password

    def generate_password(self):
        """Generates a random password

        Returns:
            str -- Random password
        """

        password = []
        length = Prompt.ask("Enter the length of the password (default: 8)", default=8)
        if str(length).lower().strip() == 'exit':
            raise UserExits
        else:
            amount = int(length)
            spinner = Halo(text=colored("Generating password", "green"), spinner=self.dots_, color="green")
            spinner.start()
            for i in range(0, amount):
                password.append(choice(choice([string.ascii_lowercase, string.ascii_uppercase, string.digits, self.specialChar_])))

            finalPass = "".join(password)
            spinner.stop()

            return finalPass

    def list_passwords(self, filename):
        """Loads a list of websites in DB

        Arguments:
            filename {str} -- DB file

        Returns:
            str -- List of passwords
        """

        if path.isfile(filename):
            with open(filename, 'r') as jsondata:
                pass_list = load(jsondata)
            
            passwords_lst = ""
            for i in pass_list:
                passwords_lst += "-- {}\n".format(i)
            
            if passwords_lst == "":
                raise PasswordFileIsEmpty
            else:
                return passwords_lst
        else:
            raise PasswordFileDoesNotExist

    def delete_db(self, filename, stored_master, entered_master):
        """Delete DB/Password file & contents
        
        Arguments:
            filename {str} -- DB/File to delete
            stored_master {str} -- Stored master password in DB
            entered_master {str} -- user-entered master password to authenticate
        
        Raises:
            MasterPasswordIncorrect: Entered password does not match stored password
            PasswordFileDoesNotExist: No file/db to delete
        """
        if path.isfile(filename):
            if stored_master == entered_master:
                # first clear the data
                spinner = Halo(text=colored("Deleting all password data...", "red"), spinner=self.dots_, color="red")
                jfile = {}
                with open(filename, 'w') as jdata:
                    dump(jfile, jdata)
                # then delete the file
                remove(filename)
                spinner.stop()
            else:
                raise MasterPasswordIncorrect
        else:
            raise PasswordFileDoesNotExist

    def delete_password(self, filename, website):
        """Deletes a single password from DB
        
        Arguments:
            filename {str} -- Password file/DB
            website {str} -- Password to delete
        
        Raises:
            PasswordNotFound: No password for given website
            PasswordFileDoesNotExist: No password file/DB
        """

        if path.isfile(filename):
            with open(filename, 'r') as jdata:
                jfile = load(jdata)
            
            try:
                jfile.pop(website)
                with open("db/passwords.json", 'w') as jdata:
                    dump(jfile, jdata, sort_keys=True, indent=4)
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist

    def delete_all_data(self, filename, master_file, stored_master, entered_master):
        """Deletes ALL data including master password and passwords stored
        
        Arguments:
            filename {str} -- Password db/file
            master_file {str} -- Where masterpassword is stored
            stored_master {str} -- The master password that is stored
            entered_master {str} -- User-entered master password. Used to verify
        Raises:
            MasterPasswordIncorrect: Passwords do not match
        """

        if path.isfile(master_file) and path.isfile(filename): # both files exist
            if stored_master == entered_master:
                spinner = Halo(text=colored("Deleting all data...", "red"), spinner=self.dots_, color="red")
                # clear data
                jfile = {}
                with open(master_file, 'w') as jdata:
                    dump(jfile, jdata)
                with open(filename, 'w') as jdata:
                    dump(jfile, jdata)
                # delete file
                remove(filename)
                remove(master_file)
                spinner.stop()
            else:
                raise MasterPasswordIncorrect
        elif path.isfile(master_file) and not path.isfile(filename): # only master password exists
            if stored_master == entered_master:
                spinner = Halo(text=colored("Deleting all data...", "red"), spinner=self.dots_, color="red")
                # clear data
                jfile = {}
                with open(master_file, 'w') as jdata:
                    dump(jfile, jdata)
                remove(master_file)
                spinner.stop()
            else:
                raise MasterPasswordIncorrect
