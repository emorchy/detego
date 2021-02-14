# Detego
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/d12645819b004168a286bf3eb52e4061)](https://app.codacy.com/gh/emorchy/detego?utm_source=github.com&utm_medium=referral&utm_content=emorchy/detego&utm_campaign=Badge_Grade)
[![Build Status](https://travis-ci.com/emorchy/detego.svg?branch=main)](https://travis-ci.com/emorchy/detego)
![GitHub last commit](https://img.shields.io/github/last-commit/emorchy/detego)
[![Requirements Status](https://requires.io/github/emorchy/detego/requirements.svg?branch=main)](https://requires.io/github/emorchy/detego/requirements/?branch=main)
![Codecov](https://img.shields.io/codecov/c/github/emorchy/detego)

### Disclaimer: Do not use for serious competition
This program is written for the intent of educational learning opportunity and may not help in correctly identifying and decoding ciphers. There are way [more](https://gchq.github.io/CyberChef/) [competent](https://github.com/Ciphey/Ciphey) [tools](https://pypi.org/project/chepy/), and I encourage you to try them before experimenting with this buggy project.

### Description
Project with the goal to decode ciphers with multiple iterations and obfuscation.

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
detego --help
```
### Encodings
Currently, the project supports multiple encodings:

base64, morse, rot, binary, and hexadecimal

If you have an encoding that you wish to be added, please create an issue or submit a pull request.
