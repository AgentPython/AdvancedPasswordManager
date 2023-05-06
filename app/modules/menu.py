from sys import exit

from pyperclip import copy, PyperclipException

from rich import box
from rich.prompt import IntPrompt, Prompt, Confirm
from rich.table import Table
from rich.console import Console

from termcolor import colored
from halo import Halo

from .encryption import DataManipulation
from .exceptions import *
from .config import prompt_menu, prompt_title

# Create console
console = Console()

# Create prompt table
table = Table(box=box.ROUNDED, show_header=False)
table.add_column("Key")
table.add_column("Value")

for key, value in prompt_menu.items():
    table.add_row(key, value)

class Manager:

    def __init__(self, obj: DataManipulation, filename: str, master_file: str, master_pass: str):
        self.obj_ = obj
        self.filename_ = filename
        self.master_file_ = master_file
        self.master_pass_ = master_pass

    def begin(self):
        # TODO : Wait
        try:
            choice = self.menu_prompt()
        except UserExits:
            raise UserExits

        console.clear()
        if choice == 5:
            raise UserExits

        if choice == 1:
            try:
                self.update_db()
                return self.begin()
            except UserExits:
                raise UserExits
        elif choice == 2:
            try:
                string = self.load_password()
                website = string.split(':')[0]
                password = string.split(':')[1]
                print(colored(f"Password for {website}: {password}", "yellow"))
                copy_to_clipboard = Confirm.ask("Copy password to clipboard?")
                if copy_to_clipboard:
                    try:
                        copy(password)
                        print(colored(f"{self.obj_.checkmark_} Password copied to clipboard", "green"))
                    except PyperclipException:
                        print(colored(f"{self.obj_.x_mark} If you see this message on Linux. Use `sudo apt-get install xsel` for copying to work", "red"))
                else:
                    pass

                return self.begin()
            except UserExits:
                raise UserExits
            except PasswordFileDoesNotExist:
                console.print(f"[red]{self.obj_.x_mark} DB not found. Try adding a password[/red]")
                return self.begin()
        elif choice == 3:
            lists = self.load_passwords()
            console.print(lists)

            return self.begin()
        elif choice == 4:
            try:
                return self.delete_password()
            except UserExits:
                raise UserExits
        elif choice == 6:
            try:
                self.delete_db(self.master_pass_)
            except MasterPasswordIncorrect:
                console.print(f"[red]{self.obj_.x_mark} Master password is incorrect {self.obj_.x_mark}[/red]")
                return self.delete_db(self.master_pass_)
            except UserExits:
                raise UserExits
        elif choice == 7: # delete ALL data
            try:
                self.delete_all_data(self.master_pass_)
            except MasterPasswordIncorrect:
                console.print(f"[red]{self.obj_.x_mark} Master password is incorrect {self.obj_.x_mark}[/red]")
                return self.delete_all_data(self.master_pass_)
            except UserExits:
                raise UserExits


    def menu_prompt(self):
        console.print(f"[magenta]{prompt_title}[/magenta]")
        console.print(table)
        choice = IntPrompt.ask("Enter a choice", default=0)
        if choice == 0:
            return self.menu_prompt()
        else:
            return choice

    def __return_generated_password(self, website):
        """Returns a generated password
        
        Arguments:
            website {str} -- website for password
        
        Raises:
            UserExits: User exits on loop prompt
        
        Returns:
            str -- A randomly generated password
        """

        try:
            generated_pass = self.obj_.generate_password()
            print(colored(generated_pass, "yellow"))

            loop = Confirm.ask("Generate a new password?")
            if loop:
                return self.__return_generated_password(website) # recursive call
            elif not loop:
                return generated_pass
        except (PasswordNotLongEnough, EmptyField):
            print(colored("Password length invalid.", "red"))
            return self.__return_generated_password(website)
        except UserExits:
            print(colored("Exiting...", "red"))
            exit()

    def update_db(self): # option 1 on main.py
        """Add or update a password in the DB
        
        Raises:
            UserExits: User enters exit at website prompt or generate prompt
        """
        try:
            self.list_passwords()
        except PasswordFileIsEmpty:
            pass
        except PasswordFileDoesNotExist:
            print(colored(f"--There are no passwords stored.--", "yellow"))

        website = Prompt.ask("Enter the website for which you want to store a password (ex. google.com)")
        if website.casefold() == "":
            self.update_db()
        elif website.casefold().strip() == "exit":
            raise UserExits
        else:

            gen_question = Confirm.ask(f"Do you want to generate a password for {website}?")
            if gen_question == False:
                password = Prompt.ask(f"Enter a password for {website}")
                self.obj_.encrypt_data(self.filename_, password, self.master_pass_, website)
            else:
                password = self.__return_generated_password(website)
                self.obj_.encrypt_data("db/passwords.json", password, self.master_pass_, website)

    def load_password(self):
        """Loads a string of websites stored and asks user to enter a 
        website, then decrypts password for entered website
        
        Raises:
            PasswordFileDoesNotExist: DB is not initialized
            UserExits: User enters exit on website prompt
        
        Returns:
            str -- string formatted in website:password
        """
        try:
            self.list_passwords()
        except PasswordFileIsEmpty:
            return self.begin()

        website = Prompt.ask("Enter website for the password you want to retrieve")

        if website.lower().strip() == "exit":
            raise UserExits
        elif website.strip() == "":
            return self.load_password()
        else:
            try:
                plaintext = self.obj_.decrypt_data(self.master_pass_, website, self.filename_)
            except PasswordNotFound:
                print(colored(f"{self.obj_.x_mark} Password for {website} not found {self.obj_.x_mark}", "red"))
                return self.load_password()
            except PasswordFileDoesNotExist:
                print(colored(f"{self.obj_.x_mark} DB not found. Try adding a password {self.obj_.x_mark}", "red"))
                return self.begin()
            
            # see https://pypi.org/project/clipboard/ for copying to clipboard
            final_str = f"{website}:{plaintext}"

            return final_str

    def load_passwords(self):
        try:
            self.list_passwords()
        except PasswordFileIsEmpty:
            return self.begin()

        try:
            plaintext_passwords = self.obj_.decrypt_all_data(self.master_pass_, self.filename_)
        except PasswordFileDoesNotExist:
            print(colored(f"{self.obj_.x_mark} DB not found. Try adding a password {self.obj_.x_mark}", "red"))
            return self.begin()

        table = Table(box=box.SQUARE_DOUBLE_HEAD)
        table.add_column("Website")
        table.add_column("Password")

        for data in plaintext_passwords:
            table.add_row(data['Website'], data['Password'])

        return table


    def delete_db(self, stored_master):
        """Menu Prompt to Delete DB/Passwords
        
        Arguments:
            stored_master {str} -- Used to authenticate, compared with inputted master password
        
        Raises:
            PasswordFileDoesNotExist: Password file not initialized
        """

        confirmation = Confirm.ask("Are you sure you want to delete the password file?")
        if confirmation:
            entered_master = Prompt.ask("Enter your master password to delete all stored passwords", password=True)
            if entered_master.lower().strip() == "exit":
                raise UserExits
            else:
                try:
                    self.obj_.delete_db(self.filename_, stored_master, entered_master)
                    print(colored(f"{self.obj_.checkmark_} Password Data Deleted successfully. {self.obj_.checkmark_}", "green"))
                    return self.begin()
                except MasterPasswordIncorrect:
                    raise MasterPasswordIncorrect
                except PasswordFileDoesNotExist:
                    print(colored(f"{self.obj_.x_mark} DB not found. Try adding a password {self.obj_.x_mark}", "red"))
                    return self.begin()
        elif not confirmation:
                print(colored("Cancelling...", "red"))
                return self.begin()

    def list_passwords(self):
        print(colored("Current Passwords Stored:", "yellow"))
        spinner = Halo(text=colored("Loading Passwords", "yellow"), color="yellow", spinner=self.obj_.dots_)
        
        try:
            lst_of_passwords = self.obj_.list_passwords(self.filename_)
            spinner.stop()
            print(colored(lst_of_passwords, "yellow"))
        except PasswordFileIsEmpty:
            lst_of_passwords = "--There are no passwords stored.--"
            spinner.stop()
            print(colored(lst_of_passwords, "yellow"))
            raise PasswordFileIsEmpty
        except PasswordFileDoesNotExist:
            raise PasswordFileDoesNotExist

    def delete_password(self):
        """Deletes a single password from DB
        
        Raises:
            UserExits: User exits
        """
        try:
            self.list_passwords()
        except PasswordFileIsEmpty:
            return self.begin()

        website = Prompt.ask("What website do you want to delete? (ex. google.com)").strip()

        if website == "exit":
            raise UserExits
        elif website == "":
            return self.delete_password()
        else:
            try:
                self.obj_.delete_password(self.filename_, website)
                print(colored(f"{self.obj_.checkmark_} Data for {website} deleted successfully.", "green"))
                return self.begin()
            except PasswordNotFound:
                print(colored(f"{self.obj_.x_mark} {website} not in DB {self.obj_.x_mark}", "red"))
                return self.delete_password()
            except PasswordFileDoesNotExist:
                print(colored(f"{self.obj_.x_mark} DB not found. Try adding a password {self.obj_.x_mark}", "red"))
                return self.begin()

    def delete_all_data(self, stored_master):
        """Deletes ALL data including master password and passwords stored. Asks for user confirmation.
        
        Arguments:
            stored_master {str} -- Master password that is stored
        
        Raises:
            UserExits: User enters exit
            MasterPasswordIncorrect: Master Passwords do not match
        """
        confirmation = Confirm.ask("Are you sure you want to delete all data?")
        if confirmation:
            entered_master = Prompt.ask("Enter your master password to delete all stored passwords", password=True)
            if entered_master.lower().strip() == "exit":
                raise UserExits
            else:
                try:
                    self.obj_.delete_all_data(self.filename_, self.master_file_, stored_master, entered_master)
                    print(colored(f"{self.obj_.checkmark_} All Data Deleted successfully. {self.obj_.checkmark_}", "green"))
                    exit()
                except MasterPasswordIncorrect:
                    raise MasterPasswordIncorrect
        elif not confirmation:
                print(colored("Cancelling...", "red"))
                return self.begin()
