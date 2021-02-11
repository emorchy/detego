# detego
Program used during CTF's to auto identify and decode ciphers.
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/d12645819b004168a286bf3eb52e4061)](https://app.codacy.com/gh/emorchy/detego?utm_source=github.com&utm_medium=referral&utm_content=emorchy/detego&utm_campaign=Badge_Grade)
[![Build Status](https://travis-ci.com/emorchy/detego.svg?branch=main)](https://travis-ci.com/emorchy/detego)
![GitHub last commit](https://img.shields.io/github/last-commit/emorchy/detego)
[![Requirements Status](https://requires.io/github/emorchy/detego/requirements.svg?branch=main)](https://requires.io/github/emorchy/detego/requirements/?branch=main)

### Installation
#### Using published package
```
pip3 install detego
```
#### Using local source
```
pip3 install -r requirements.txt
pip3 install -e .
```
### Running
To see the arguments to run the program:
```
python3 -m detego --help
```
### Encodings
Currently, the project supports multiple encodings:

base64, morse, rot, binary, and hexadecimal

If you have an encoding that you wish to be added, please create an issue or submit a pull request.
