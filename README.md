# APassword Manager

##### Documents for v1.0.0-pre-alpha

APassword Manager is a simple Python password manager. It allows you to securely save secrets with a simple CLI interface.

## Features
- Local database, each email and passwords are encrypted with a unique code using AES encryption
- Master key is hashed
- Possibility to create an unlimited number of managers
- Clipboard detected
- Password suggestions for password generator

## Usage
![](./assets/How-To-Use.svg)

## Installation and setup
APassword Manager 0.1.x can only be run locally.

### Cloning the project
``` bash
git clone https://github.com/AgentPython/AdvancedPasswordManager.git
```

### Install dependencies
*optional: virtual environment*

#### poetry

```bash
poetry install
```

#### pip
```bash
pip install -r requirements.txt
```

### Run
#### poetry
``` bash
poetry run app
```

#### python
``` bash
python -m app.main
```

## Upcoming
*Release date : May 13, 2023 (in a week)*
<br>
APasswordManager 0.2.x requires `sqlcipher` to be installed on your machine.
APasswordManager is packaged so you can use it in your project or in your terminal.
Which means can be installed with `pip install apasswordmanager`

### Features
- External database with SQLite + SQLCipher
- Adding unique salt for every passwords, emails, and notes.
- Import or export in JSON
