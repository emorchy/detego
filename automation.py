#!/bin/python3
import argparse
import math
import matplotlib
import re
import codecs
import base64
from tqdm import tqdm 
import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)

#TODO analysis of what the text is (hex, binary, etc), but also include arguments to automatically do it
#TODO things to look for (program will stop if code matches user defined key ('htb{' or english.txt)

def parse_command_line():
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("ciphertext", help="ciphertext here", nargs='?')
	group.add_argument("-f", "--file", help="Option cipherfile in place of ciphertext", nargs='?')
	parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
	parser.add_argument("-s", "--search", help="Program will know it has successfully decoded if output contains user defined string")
	parser.add_argument("-d", "--dictionary", help="Program will know it has successfully decoded if output contains English words")
	parser.add_argument("-n", "--number", help="The number of English words before the program is flagged as correct", const=3, type=int, nargs='?', default=3)
	parser.add_argument("-i", "--iteration", help="The number of iterations the program will do", const=3, type=int, nargs='?', default=3)
	parser.add_argument("-r", "--rot", help="Run all ROT's (1-25) instead of just ROT13", action="store_true")

	return parser

MORSE_CODE_DICT = { 'A':'.-', 'B':'-...', 
                    'C':'-.-.', 'D':'-..', 'E':'.', 
                    'F':'..-.', 'G':'--.', 'H':'....', 
                    'I':'..', 'J':'.---', 'K':'-.-', 
                    'L':'.-..', 'M':'--', 'N':'-.', 
                    'O':'---', 'P':'.--.', 'Q':'--.-', 
                    'R':'.-.', 'S':'...', 'T':'-', 
                    'U':'..-', 'V':'...-', 'W':'.--', 
                    'X':'-..-', 'Y':'-.--', 'Z':'--..', 
                    '1':'.----', '2':'..---', '3':'...--', 
                    '4':'....-', '5':'.....', '6':'-....', 
                    '7':'--...', '8':'---..', '9':'----.', 
                    '0':'-----', ', ':'--..--', '.':'.-.-.-', 
                    '?':'..--..', '!':'-.-.--', '/':'-..-.', 
                    '-':'-....-', '(':'-.--.', ')':'-.--.-'} 

def answer(a, b):
	print(Fore.GREEN + a + Style.BRIGHT + b)
def info(a):
	print(Fore.BLUE + a)

class Decode:
	def decode(self):
		try:
			plaintext = self.decode('utf-8')
			return plaintext
		except:
			plaintext = "ϴ"
			return plaintext
	def binary(self):
		clean = re.sub('[\W_]', '', self) # gets rid of delimiters
		split = [clean[i:i+8] for i in range(0, len(clean), 8)]	# splits string into groups of 8
		byte_list = []
		for i in range(len(split)): # convert each binary string to its corresponding byte
			binary = bytes([int(split[i], base=2)]) # converts binary string to decimal to binary literal
			plaintext = Decode.decode(binary)
			byte_list.append(plaintext)
		return ''.join(byte_list)

	def base64(self):
		bases = base64.b64decode(self)
		return Decode.decode(bases)

	def rot(self, key):
		LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
		letters = 'abcdefghijklmnopqrstuvwxyz'
		translated = ''
		for symbol in self:
			if symbol in LETTERS:
				num = LETTERS.find(symbol)
				num = num - key
				if num < 0:
					num = num + len(LETTERS)
				translated = translated + LETTERS[num]
			elif symbol in letters:
				num = letters.find(symbol)
				num = num - key
				if num < 0:
					num = num + len(letters)
				translated = translated + letters[num]
			else:
				translated = translated + symbol
		return translated

	def morse(self):
		self += ' '
		decipher = ''
		mycitext = ''
		for myletter in self:
			# checks for space
			if (myletter != ' '):
				i = 0
				mycitext += myletter
			else:
				i += 1
				if i == 2 :
					decipher += ' '
				else:
					decipher += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT.values()).index(mycitext)]
					mycitext = ''
		return decipher

class Manipulate:
	def reverse(self):
		return self[::-1]

def identify(cipher):
	candidates = []
	base64 = re.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$")
	binary = re.compile("^[01\W_]+$")
	rot = re.compile("^[A-Za-z0-9\W]+$")
	hex = re.compile("^[A-Fa-f0-9]+$")
	morse = re.compile("^[.\- /]+$")

	if cipher.isascii():
		info("Ciphertext is ascii")
	if cipher.isdigit():
		info("Ciphertext is a number")
	if cipher.isalpha():
		info("Ciphertext is all letters")
	if cipher.isupper():
		info("Ciphertext is uppercase")
	if cipher.islower():
		info("Ciphertext is lowercase")

	if binary.match(cipher):
		info("Ciphertext may be binary")
		plaintext = Decode.binary(cipher)
		answer("Binary decode (Ø means unprintable): ", plaintext)
		candidates.append(plaintext)
	if base64.match(cipher):
		info("Ciphertext may be base64")
		plaintext = Decode.base64(cipher)
		answer("Base64 decode (Ø means unprintable): ", plaintext)
		candidates.append(plaintext)
	if rot.match(cipher):
		info("Ciphertext may be ROT")
		for i in range(rot_min, rot_max):
			plaintext = Decode.rot(cipher, i).rstrip()
			answer("ROT%d decode: " % i, plaintext)
			candidates.append(plaintext)
	if morse.match(cipher):
		info("Ciphertext may be morse")
		plaintext = Decode.morse(cipher.replace('/', ''))
		answer("Morse decode: ", plaintext)
		candidates.append(plaintext)
	if hex.match(cipher):
		info("Ciphertext may be hex")
	return candidates

class Check:
	def string(self, pt):
		if search in pt:
			return True
	def dictionary(self, pt):
		count = 0
		flag = re.split(' | ,| _| -| !| .| +| ', pt)
		for line in dictionary:
			for i in range(len(flag)):
				if flag[i].lower() == line:
					count += 1
			if count >= num:
				return True
	def __init__(self, plaintext):
		self.plaintext = plaintext
	def __bool__(self):
		try:
			if self.string(self.plaintext) == True:
				return True
		except:
			pass
		try:
			if self.dictionary(self.plaintext) == True:
				return True
		except:	
			pass
		return False
		

if __name__ == '__main__':
	args = parse_command_line().parse_args()
	if args.ciphertext != None:
		cipher = []
		cipher.append(args.ciphertext)
	if args.file != None:
		with open(args.file, 'r') as file:
			cipher = file.read().replace('\n', '')
	if args.dictionary != None:
		with open(args.dictionary, 'r') as file:
			dictionary = file.read()
			dictionary = dictionary.split('\n')
	if args.search != None:
		search = args.search

	rot_min = 13
	rot_max = 14
	if args.rot:
		rot_min = 1
		rot_max = 26

	num = args.number
	iteration = args.iteration

	for i in range(1, 1 + iteration):
		print("Iteration %d:" % i)
		for j in range(len(cipher)):
			candidates = identify(cipher[j])
			print("Candidates %s, cipher %s" % (candidates, cipher))
			for k in tqdm (range (len(candidates)), desc="Checking for matches..."):
				if Check(candidates[k]):
					print(Fore.RED + Style.BRIGHT + "\nFinal: %s\n" % candidates[k])
					exit(0)
		cipher = candidates
