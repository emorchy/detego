#!/bin/python3
import argparse
import re
import base64
import colorama
from tqdm import tqdm
from colorama import Fore, Style
colorama.init(autoreset=True)


def parse_command_line():
    parser = argparse.ArgumentParser(prog='detego')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("ciphertext", help="ciphertext here", nargs='?')
    group.add_argument("-f", "--file", help="Option cipherfile in place of ciphertext", nargs='?')
    parser.add_argument("-v", "--verbose", help="Increase output verbosity (incremental)", action='count', default=0)
    parser.add_argument("-s", "--string", help="Program will stop if it finds user defined string")
    parser.add_argument("-d", "--dictionary", help="Program will stop if it contains words in dictionary")
    parser.add_argument("-n", "--number", help="The number of English words before the program is flagged as correct", const=3, type=int, nargs='?', default=3)
    parser.add_argument("-i", "--iteration", help="The number of iterations the program will do", const=3, type=int, nargs='?', default=1)
    parser.add_argument("-u", "--userdefined", help="User defines what to decode (type '--listuser' to list arguments)", type=str, nargs='?')
    parser.add_argument("--listuser", help="Lists user defined arguments", action="store_true")
    return parser

MORSE_DICT = (
    ('A', '.-'), ('B', '-...'), ('C', '-.-.'), ('D', '-..'),
    ('E', '.'), ('F', '..-.'), ('G', '--.'), ('H', '....'),
    ('I', '..'), ('J', '.---'), ('K', '-.-'), ('L', '.-..'),
    ('M', '--'), ('N', '-.'), ('O', '---'), ('P', '.--.'),
    ('Q', '--.-'), ('R', '.-.'), ('S', '...'), ('T', '-'),
    ('U', '..-'), ('V', '...-'), ('W', '.--'), ('X', '-..-'),
    ('Y', '-.--'), ('Z', '--..'), ('0', '-----'), ('1', '.----'),
    ('2', '..---'), ('3', '...--'), ('4', '....-'), ('5', '.....'),
    ('6', '-....'), ('7', '--...'), ('8', '---..'), ('9', '----.'),
    (',', '--..--'), ('.', '.-.-.-'), ('?', '..--..'), (';', '-.-.-.'),
    (':', '---...'), ("'", '.----.'), ('-', '-....-'), ('/', '-..-.'),
    ('(', '-.--.-'), (')', '-.--.-'), ('_', '..--.-'), ('!', '-.-.--'),
    ('Ä', '.-.-'), ('À', '.--.-'), ('Ö', '---.'), ('CH', '----'),
    ('Ü', '..--'), ('È', '.-..-'), ('Ŝ', '...-.'), ('Þ', '.--..'),
    ('É', '..-..')
)

def answer(a, b):
    print(Fore.GREEN + "{} decode: ".format(a) + Style.BRIGHT + "{}".format(b))
def info(a):
    print(Fore.BLUE + a)

class Decode:
    def bytedecode(self):
        try:
            plaintext = self.decode('utf-8')
            return plaintext
        except:
            return ''
    def binary(self):
        clean = re.sub(r'[\W_]', '', self) # gets rid of delimiters
        split = [clean[i:i+8] for i in range(0, len(clean), 8)] # splits string into groups of 8
        byte_list = []
        for i in split: # convert each binary string to its corresponding byte
            binary = bytes([int(i, base=2)]) # converts binary string to decimal to binary literal
            plaintext = Decode.bytedecode(binary)
            byte_list.append(plaintext)
        return ''.join(byte_list)
    def base64(self):
        bases = base64.b64decode(self)
        return Decode.bytedecode(bases)
    def rot(self):
        LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        letters = 'abcdefghijklmnopqrstuvwxyz'
        #numbers = '0123456789'
        translated = []
        for i in range(1,25):
            char = []
            for symbol in self:
                if symbol.isupper(): charset = LETTERS   # defines which charset to shift
                elif symbol.islower(): charset = letters
                #elif symbol.isdigit(): charset = numbers
                else:
                    char.append(symbol) # char will not be shifted if it doesn't belong to any charset
                    continue
                num = charset.find(symbol) # finds index number of char in charset
                num = (num + i) % len(charset) # finds the shifted char in charset while staying in range
                char.append(charset[num]) # add to char list
            translated.append("".join(char)) # combine char list into one string
        return translated # return every string from every rot iterated
    def hexadecimal(self):
        try:
            charlist = re.findall('[0-9A-Fa-f]{2}',self)
            chars = ''.join(charlist)
            translated = bytearray.fromhex(chars).decode()
            return translated
        except:
            return None

    def morse(self):
        code = self.strip()
        text = []
        for morse_word in re.split(r"[/\\]", code): # splits into words on slash
            word = []
            for morse_char in re.split(r"[ ]", morse_word): # splits into letters on space
                for plain, char in MORSE_DICT:
                    if char == morse_char:
                        word.append(plain)
            text.append(''.join(word))
        return ' '.join(text)

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
                        ("morse", r"^[\s]*[.-]{1,5}(?:[ \t/\\]+[.-]{1,5})*(?:[ \t/\\]+[.-]{1,5}(?:[ \t/\\]+[.-]{1,5})*)*[\s]*$"),
                    )
        candidates = [] #prepares candidates for multiple iterations
        for encoder, regex in encodings: #for each string found in the encoding list
            if re.compile(regex).match(cipher): #if the regex of the encoder matches the ciphertext
                if verbose >= 2:
                    info("Ciphertext may be {}".format(encoder))
                try:
                    decoded = getattr(Decode, encoder)(cipher) #pass along the ciphertext and the encoding type to the decoder
                    if encoder == "rot": # temporary solution
                        if verbose >= 1:
                            for i, code in enumerate(decoded):
                                answer(encoder + str(i+1), code)
                        candidates.extend(decoded)
                    else:
                        if decoded: # if the program returns actual code
                            if verbose >= 1:
                                answer(encoder, decoded)
                            candidates.append(decoded) #add the possible plaintext to the candidate list
                        else:
                            raise Exception("Did not return a utf-8 printable value")
                except Exception as e:
                    if verbose == 2:
                        info("Could not decode using {}, Error: {}".format(encoder, e))
        return candidates #returns possible candidates of plaintext from decoding

class Define:
    def __init__(self, defined, code):
        """Class and function decodes ciphertext using user defined character interpreted as an encoder."""
        for encoder in defined:
            try:
                if encoder == '6':
                    code = Decode.base64(code)
                    answer("Base64", code)
                elif encoder.lower() == 'm':
                    code = Decode.morse(code)
                    answer("Morse", code)
                elif encoder.lower() == 'b':
                    code = Decode.binary(code)
                    answer("Binary", code)
                elif encoder.lower() == 'h':
                    code = Decode.hexadecimal(code)
                    answer("Hexadecimal", code)
                elif encoder.lower() == 'r':
                        code = Decode.rot(code)
                        for j, code in enumerate(code):
                            answer("rot{}".format(str(j+1)), code)
            except Exception as e:
                info("{} did not work, Error: {}".format(encoder, e))

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

def main():
    args = parse_command_line().parse_args()
    if args.ciphertext != None:
        ciphers = [args.ciphertext]
    if args.file != None:
        with open(args.file, 'r') as file:
            ciphers = [file.read().replace('\n', '')]
    dictionary = args.dictionary
    if args.dictionary != None:
        with open(args.dictionary, 'r') as file:
            dictionary = file.read()
            dictionary = dictionary.split('\n')
    if args.listuser:
        print('''
        base64  =   6
        morse   =   m
        binary  =   b
        rot     =   r

        Example: '6b' decodes base64 and decodes binary
        ''')
        exit(0)
    string = args.string

    if args.userdefined != None:
        defined = list(args.userdefined)
        code = ciphers[0]
        Define(defined, code)
        exit(0)

    num = args.number
    iteration = args.iteration
    verbose = args.verbose

    if dictionary == None and string == None:
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
        if verbose == 1:
            info("Iteration {}".format(i))
        for cipher in ciphers: # for every cipher in ciphers list
            candidates += Identify.main(cipher, verbose) # find potential candidates
            if verbose == 3:
                print("Candidates %s, ciphers %s" % (candidates, ciphers))
            if check == 1:
                for k in tqdm(candidates, desc="Checking for matches..."):
                    if Check(k, string, dictionary, num):
                        print(Fore.RED + Style.BRIGHT + "\nFinal: %s\n" % k)
                        exit(0)
        ciphers = candidates # ciphers become old candidates
        if not candidates:
            print(Fore.RED + Style.BRIGHT + "\nNot Found!\n")
            exit(1)
