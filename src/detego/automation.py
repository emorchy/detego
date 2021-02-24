#!/bin/python3
import argparse
import re
import colorama
from tqdm import tqdm
from colorama import Fore, Style
colorama.init(autoreset=True)
from .decode import Decode


def parse_command_line():
    parser = argparse.ArgumentParser(prog='detego')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("ciphertext", help="ciphertext here", nargs='?')
    group.add_argument("-f", "--file", help="Option cipherfile in place of ciphertext", nargs='?')
    parser.add_argument("-v", "--verbose", help="Increase output verbosity (incremental)", action='count', default=0)
    parser.add_argument("-s", "--search", help="Program will stop if it finds user defined string")
    parser.add_argument("-d", "--dictionary", help="Program will stop if it contains words in dictionary")
    parser.add_argument("-n", "--number", help="The number of English words before the program is flagged as correct", const=3, type=int, nargs='?', default=3)
    parser.add_argument("-i", "--iteration", help="The number of iterations the program will do", const=3, type=int, nargs='?', default=1)
    parser.add_argument("-u", "--userdefined", help="User defines what to decode (type '--listuser' to list arguments)", type=str, nargs='?')
    parser.add_argument("--listuser", help="Lists user defined arguments", action="store_true")
    return parser

def answer(a, b):
    print(Fore.GREEN + "{} decode: ".format(a) + Style.BRIGHT + "{}".format(b))
def info(a):
    print(Fore.BLUE + a)

class Manipulate:
    def reverse(self):
        return self[::-1]

class Identify: #class that automates identification of ciphertext (faster than brute forcing)
    def main(cipher, verbose):
        encodings = (
                        ("base64", r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"),
                        ("binary", r"^([01]+[\W_]?)+$"),
                        ("rot", r"^([A-Za-z]+[0-9\W]*)+$"),
                        ("hexadecimal", r"^.*[A-Fa-f0-9]{2}.*$"),
                        ("morse", r"^[\s]*[.-]{1,6}(?:[ \t\/\\]+[.-]{1,6})*(?:[ \t\/\\]+[.-]{1,6}(?:[ \t\/\\]+[.-]{1,6})*)*[\s]*$"),
                        ("vigenere", r"^[A-Za-z]+$"),
                    )
        candidates = [] #prepares candidates for multiple iterations
        for encoder, regex in encodings: #for each string found in the encoding list
            if re.compile(regex).match(cipher): #if the regex of the encoder matches the ciphertext
                if verbose >= 2:
                    info("Ciphertext may be {}".format(encoder))
                try:
                    decoded = getattr(Decode, encoder)(cipher) #pass along the ciphertext and the encoding type to the decoder
                    if isinstance(decoded, list):
                        if verbose >= 1:
                            for i, code in enumerate(decoded):
                                answer(encoder + str(i+1), code)
                        candidates.extend(decoded) #add the possible plaintext to the candidate list
                    elif isinstance(decoded, str):
                        if decoded != None: # if the program is utf-8
                            if verbose >= 1:
                                answer(encoder, decoded)
                            candidates.append(decoded)
                        else:
                            raise Exception("Did not return a utf-8 printable value")
                except Exception as e:
                    if verbose == 2:
                        info("Could not decode using {}, Error: {}".format(encoder, e))
        return candidates #returns possible candidates of plaintext from decoding

def define(defined, code):
    """Class and function decodes ciphertext using user defined character interpreted as an encoder."""
    decode = list(defined)
    candidates = [code]
    decoded = []
    for encoder in decode:
        try:
            types = (
                    ('base64', 'B'),
                    ('morse', 'm'),
                    ('binary', 'b'),
                    ('hexadecimal', 'h'),
                    ('rot', 'r'),
                    ('vigenere', 'v'),
                    )
            for index, tup in enumerate(types):
                if encoder in tup:
                    temp = []
                    for candidate in candidates:
                        decoded = getattr(Decode, tup[0])(candidate)
                        if decoded:
                            if isinstance(decoded, list):
                                temp += decoded
                                for count, plain in enumerate(decoded):
                                    answer("{}{}".format(tup[0], str(count+1)), plain)
                            else:
                                temp += [decoded]
                                answer(tup[0], decoded)
                    candidates = temp
        except Exception as e:
            info("{} did not work, Error: {}".format(defined, e))
    return candidates

class Check:
    def check_string(self):
        if self.string.lower() in self.plaintext:
            return True
    def check_dictionary(self):
        count = 0
        flag = re.split(' | ,| _| -| !| .| +| ', self.plaintext)
        for line in self.dictionary:
            for i in flag:
                if i == line:
                    count += 1
            if count >= self.num:
                return True
    def __init__(self, plaintext, string, dictionary, num):
        self.plaintext = plaintext.lower()
        self.string = string
        self.dictionary = dictionary
        self.num = num
    def __bool__(self):
        if self.string != None:
            if self.check_string() == True:
                return True
        if self.dictionary != None:
            if self.check_dictionary() == True:
                return True
        return False

def parse_analyze():
    args = parse_command_line().parse_args()
    dictionary = None
    if args.ciphertext:
        ciphers = [args.ciphertext]
    elif args.file:
        with open(args.file, 'r') as file:
            ciphers = [file.read().replace('\n', '')]
    if args.dictionary:
        with open(args.dictionary, 'r') as file:
            dictionary = file.read()
            dictionary = dictionary.split('\n')
    if args.listuser:
        print('''
        base64      =   B
        morse       =   m
        binary      =   b
        rot         =   r
        vigenere    =   v

        Example: 'Br' decodes base64 and then brute forces a rot cipher
        ''')
        exit(0)
    return ciphers, args.iteration, args.verbose, dictionary, args.search, args.number, args.userdefined

def main():
    ciphers, iteration, verbose, dictionary, search, number, userdefined = parse_analyze()
    if userdefined:
        candidates = define(userdefined, ciphers[0])
        exit(0)

    if not dictionary and not search:
        check = 0
        info("No checks will run")
        if verbose == 0:
            info("Increasing verbosity because no checks defined")
            verbose = 1
    else:
        check = 1

# if one cipher returns two candidates, the next iteration will check two ciphers. If they both return two candidates, the pattern is 1,2,4,8,16
    for i in range(1, 1 + iteration): # for every iteration
        candidates = [] # declare/reset candidates variable
        if verbose >= 1:
            info("Iteration {}".format(i))
        for cipher in ciphers: # for every cipher in ciphers list
            candidates += Identify.main(cipher, verbose) # find potential candidates
            if verbose == 3:
                print("Candidates %s, ciphers %s" % (candidates, ciphers))
            if check == 1:
                for k in tqdm(candidates, desc="Checking for matches..."):
                    if Check(k, search, dictionary, number):
                        print(Fore.RED + Style.BRIGHT + "\nFinal: %s\n" % k)
                        exit(0)
        ciphers = candidates # ciphers become old candidates
        if not candidates:
            print(Fore.RED + Style.BRIGHT + "\nNot Found!\n")
            exit(1)
