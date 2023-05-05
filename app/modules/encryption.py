from halo import Halo
from termcolor import colored
from os import path
from json import load, dump

class DataManipulation:
    def __init__(self):
        self.dots_ = {"interval": 80, "frames": ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]}
        self.checkmark_ = "\u2713"
        self.x_mark = "\u2717"

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
