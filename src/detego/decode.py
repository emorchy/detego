#!/bin/python3
import re
import base64

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

class Decode:

    def utf8(self): # attempt to decode binary, else return None
        try:
            plaintext = self.decode('utf-8')
            return plaintext
        except ValueError:
            return None

    def binary(self):
        clean = re.sub(r'[\W_]', '', self) # gets rid of delimiters
        split = [clean[i:i+8] for i in range(0, len(clean), 8)] # splits string into groups of 8
        byte_list = []
        for i in split: # convert each binary string to its corresponding byte
            binary = bytes([int(i, base=2)]) # converts binary string to decimal to binary literal
            plaintext = Decode.utf8(binary)
            byte_list.append(plaintext)
        return ''.join(byte_list)

    def base64(self):
        bases = base64.b64decode(self)
        return Decode.utf8(bases)

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
        except ValueError:
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
