import string

from random import choice
from os import path, remove
from json import load, dump

from halo import Halo
from termcolor import colored
from rich.prompt import Prompt
from Crypto.Cipher import AES
from base64 import b64decode, b64encode

from .exceptions import *


class DataManipulation:
    def __init__(self):
        self.dots_ = {"interval": 80, "frames": ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]}
        self.checkmark_ = "\u2713"
        self.x_mark = "\u2717"
        self.specialChar_ = "!@#$%^&*()-_"

    def encrypt(self, message, key):
        cipher = AES.new(key, AES.MODE_EAX)
        encrypted, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        encrypted_string = b64encode(encrypted)
        tag_string = b64encode(tag)
        nonce_string = b64encode(cipher.nonce)
        # print('Cipher Message:', encrypted)
        # print('Cipher Tag:', tag)
        # print('Cipher Nonce:', cipher.nonce)
        # print('Message:', encrypted_string)
        # print('Tag:', tag_string)
        # print('Nonce:', nonce_string)
        return encrypted_string.hex(), tag_string.hex(), nonce_string.hex()

    def decrypt(self, message, tag, key, nonce):
        # print('Cipher Message:', message)
        # print('Cipher Tag:', tag)
        # print('Cipher Nonce:', nonce)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        res_message = cipher.decrypt_and_verify(message, tag)
        return res_message


    def __save_password(self, filename, data, tags, nonce, website):
        """Saves password to Database

        Arguments:
            filename {str} -- DB to save to
            data {obj} -- Password that will be saved
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
                jfile[website]["tags"] = tags
                jfile[website]['data'] = data
                with open(filename, 'w') as jsondata:
                    dump(jfile, jsondata, sort_keys=True, indent=4)
            except KeyError:
                with open(filename, 'r') as jsondata:
                    jfile = load(jsondata)
                jfile[website] = {}
                jfile[website]["nonce"] = nonce
                jfile[website]["data"] = data
                jfile[website]["tags"] = tags
                with open(filename, 'w') as jsondata:
                    dump(jfile, jsondata, sort_keys=True, indent=4)
        else:
            jfile = {website: {}}
            jfile[website]["nonce"] = nonce
            jfile[website]["data"] = data
            jfile[website]["tags"] = tags
            with open(filename, 'w') as jsondata:
                dump(jfile, jsondata, sort_keys=True, indent=4)
        spinner.stop()
        print(colored(f"{self.checkmark_} Saved successfully. Thank you!", "green"))

    def encrypt_data(self, filename, data, master_pass, website):
        """Encrypts the password and saves it to the DB

        Arguments:
            filename {str} -- DB to save to
            data {obj} -- Password that will be saved
            master_pass {str} -- Master password to encrypt the password
            website {str} -- Name of the website for the given password
        """

        concatenated_password = master_pass + "================"
        key = concatenated_password[:16].encode('utf-8')
        # print('===== Encrypt =====')
        # print('Key:', key)
        # print('===== Email =====')
        encrypted_email, encrypted_email_tag, encrypted_email_nonce = self.encrypt(data['email'], key)
        # print('===== Password =====')
        encrypted_password, encrypted_password_tag, encrypted_password_nonce = self.encrypt(data['password'], key)
        tags = {
            "email": encrypted_email_tag,
            "password": encrypted_password_tag
        }

        data = {
            "email": encrypted_email,
            "password": encrypted_password
        }

        nonce = {
            "email": encrypted_email_nonce,
            "password": encrypted_password_nonce
        }
        self.__save_password(filename, data, tags, nonce, website)


    def decrypt_all_data(self, master_pass, filename):

        plaintext_data = []
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
            nonce_password_byte = bytes.fromhex(encrypted["nonce"]["password"])
            nonce_password = b64decode(nonce_password_byte)
            nonce_email_byte = bytes.fromhex(encrypted["nonce"]["email"])
            nonce_email = b64decode(nonce_email_byte)

            tag_password_byte = bytes.fromhex(encrypted["tags"]["password"])
            tag_password = b64decode(tag_password_byte)
            tag_email_byte = bytes.fromhex(encrypted["tags"]["email"])
            tag_email = b64decode(tag_email_byte)

            password_byte = bytes.fromhex(encrypted['data']["password"])
            email_byte = bytes.fromhex(encrypted['data']["email"])
            password = b64decode(password_byte)
            email = b64decode(email_byte)
            plaintext_email = self.decrypt(email, tag_email, master_pass_encoded, nonce_email).decode('utf-8')
            plaintext_password = self.decrypt(password, tag_password, master_pass_encoded, nonce_password).decode('utf-8')
            plaintext_data.append({ "Website": website, "Password": plaintext_password, "Email": plaintext_email })

        return plaintext_data


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
                nonce_password_byte = bytes.fromhex(jfile[website]["nonce"]["password"])
                nonce_password = b64decode(nonce_password_byte)
                nonce_email_byte = bytes.fromhex(jfile[website]["nonce"]["email"])
                nonce_email = b64decode(nonce_email_byte)

                tag_password_byte = bytes.fromhex(jfile[website]["tags"]["password"])
                tag_password = b64decode(tag_password_byte)
                tag_email_byte = bytes.fromhex(jfile[website]["tags"]["email"])
                tag_email = b64decode(tag_email_byte)

                password_byte = bytes.fromhex(jfile[website]['data']["password"])
                email_byte = bytes.fromhex(jfile[website]['data']["email"])
                password = b64decode(password_byte)
                email = b64decode(email_byte)
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist

        formatted_master_pass = master_pass + "================" 
        master_pass_encoded = formatted_master_pass[:16].encode('utf-8') 
        # print('====== decrypt ======')
        # print('Key:', master_pass_encoded)
        # print('====== Password ======')
        plaintext_password = self.decrypt(password, tag_password, master_pass_encoded, nonce_password).decode('utf-8')
        # print('====== Email ======')
        plaintext_email = self.decrypt(email, tag_email, master_pass_encoded, nonce_email).decode('utf-8')

        plaintext_data = {"Website": website, "Email": plaintext_email, "Password": plaintext_password}
        return plaintext_data

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
