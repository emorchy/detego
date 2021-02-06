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
#TODO create a class about just passive statistics
#TODO be able to list what it decodes
#TODO fix unprintable characters
#TODO fix rot key
#TODO document my code

def parse_command_line():
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("ciphertext", help="ciphertext here", nargs='?')
	group.add_argument("-f", "--file", help="Option cipherfile in place of ciphertext", nargs='?')
	parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
	parser.add_argument("-s", "--search", help="Program will know it has successfully decoded if output contains user defined string")
	parser.add_argument("-d", "--dictionary", help="Program will know it has successfully decoded if output contains English words")
	parser.add_argument("-n", "--number", help="The number of English words before the program is flagged as correct", const=3, type=int, nargs='?', default=3)
	parser.add_argument("-i", "--iteration", help="The number of iterations the program will do", const=3, type=int, nargs='?', default=1)
	parser.add_argument("-r", "--rot", help="Run all ROT's (1-25) instead of just ROT13", action="store_true")
	parser.add_argument("-u", "--userdefined", help="User defines what to decode (type '--listuser' to list arguments)", type=str, nargs='?')
	parser.add_argument("--listuser", help="Lists user defined arguments", action="store_true")
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
		    '-':'-....-', '(':'-.--.', ')':'-.--.-',
		    '=':'-...-'}

def answer(a, b):
	print(Fore.GREEN + "{} decode: ".format(a) + Style.BRIGHT + "{}".format(b))
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
		clean = re.sub(r'[\W_]', '', self) # gets rid of delimiters
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
	def rot(self, rot_min, rot_max):
		LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
		letters = 'abcdefghijklmnopqrstuvwxyz'
		numbers = '0123456789'
		translated = []
		for i in range(rot_min, rot_max):
			char = []
			for symbol in self:
				if symbol.isupper(): charset = LETTERS	 # defines which charset to shift
				elif symbol.islower(): charset = letters 
				elif symbol.isdigit(): charset = numbers 
				else:
					char.append(symbol) # char will not be shifted if it doesn't belong to any charset
					continue
				num = charset.find(symbol) # finds index number of char in charset
				num = (num + i) % len(charset) # finds the shifted char in charset while staying in range
				char.append(charset[num]) # add to char list
			translated.append("".join(char)) # combine char list into one string
		return translated # return every string from every rot iterated
	def hexadecimal(self):
		chars = []
		if ' ' in self:
			for i in self.split(" "):
				translated = bytearray.fromhex(i).decode()
		if '0x' in self:
			for i in self.split("0x"):
				translated = bytearray.fromhex(i).decode()
		else:
			translated = bytearray.fromhex(self).decode()
		return translated
	def morse(self):
		code = self.strip()
		decipher, pending = '','' # declare two empty string variables
		space = re.compile(r"[ \t]") # tab or space
		word = re.compile(r"[/\\]") # forward of backward slash
		for ditdah in code:
			if space.match(ditdah):
				decipher += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT.values()).index(pending)] # decode in pending string
				pending = '' # reset pending string
			elif word.match(ditdah):
				decipher += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT.values()).index(pending)]
				pending = ''
				decipher += ' ' # because / or \ represents a new word, so adds space
			else:
				pending += ditdah # add '.' or '_' to pending string, decoded and added to decipher after delimiter
		decipher += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT.values()).index(pending)] # required because code ends without delimiter
		return decipher

class Manipulate:
	def reverse(self):
		return self[::-1]

class Identify: #class that automates identification of ciphertext (faster than brute forcing)
	def regex(encoder): #establishes what each possible encoded ciphertext looks like using regex
		base64 = re.compile(r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$")
		binary = re.compile(r"^[01\W_]+$")
		rot = re.compile(r"^[A-Za-z0-9\W]+$")
		hexadecimal = re.compile(r"^[0]?[xX]?[A-Fa-f0-9 ]+$")
		morse = re.compile(r"^[\s]*[.-]{1,5}(?:[ \t/\\]+[.-]{1,5})*(?:[ \t/\\]+[.-]{1,5}(?:[ \t/\\]+[.-]{1,5})*)*[\s]*$")
		return eval(encoder)
	def main(cipher):
		encodings = ["base64", "binary", "rot", "hexadecimal", "morse"] #lists each function name (REDO IN TODO)
		candidates = [] #prepares candidates for multiple iterations
		for encoder in encodings: #for each string found in the encoding list
			if Identify.regex(encoder).match(cipher): #if the regex of the encoder matches the ciphertext
				info("Ciphertext may be {}".format(encoder))
				try:
					if encoder == "rot": # temporary solution
						global rot_min, rot_max
						decoded = Decode.rot(cipher, rot_min, rot_max) #pass along the ciphertext and the encoding type to the decoder
						for i in range(len(decoded)):
							answer(encoder + str(i+1), decoded[i])
						candidates.extend(decoded)
					else:
						decoded = getattr(Decode, encoder)(cipher) #pass along the ciphertext and the encoding type to the decoder
						answer(encoder, decoded)
						candidates.append(decoded) #add the possible plaintext to the candidate list
				except Exception as e:
					print("Could not decode using {}, Error: {}".format(encoder, e))
		return candidates #returns possible candidates of plaintext from decoding

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
			cipher = []
			cipher.append(file.read().replace('\n', ''))
	if args.dictionary != None:
		with open(args.dictionary, 'r') as file:
			dictionary = file.read()
			dictionary = dictionary.split('\n')
	if args.search != None:
		search = args.search
	if args.listuser:
		print('''
		base64	=   6
		morse	=   m
		binary	=   b
		rot	=   r

		Example: '6b' decodes base64 and decodes binary
		''')
		exit(0)

	rot_min = 13
	rot_max = 14
	if args.rot:
		rot_min = 1
		rot_max = 26

	if args.userdefined != None:
		defined = list(args.userdefined)
		code = cipher[0]
		for i in defined:
			try:
				if i == '6':
					code = Decode.base64(code)
					answer("Base64 decode (Ø means unprintable): ", code)
				elif i.lower() == 'm':
					code = Decode.morse(code)
					answer("Morse decode (Ø means unprintable): ", code)
				elif i.lower() == 'b':
					code = Decode.binary(code) 
					answer("Binary decode (Ø means unprintable): ", code)
				elif i.lower() == 'r':
					for j in range(rot_min, rot_max):
						code = Decode.rot(code, j).rstrip()
						answer("Rot decode (Ø means unprintable): ", code)
			except:
				print("{} did not work".format(i))
		exit(0)

	num = args.number
	iteration = args.iteration

	for i in range(1, 1 + iteration):
		print("Iteration %d:" % i)
		for j in range(len(cipher)):
			candidates = Identify.main(cipher[j])
			print("Candidates %s, cipher %s" % (candidates, cipher))
			for k in tqdm (range (len(candidates)), desc="Checking for matches..."):
				if Check(candidates[k]):
					print(Fore.RED + Style.BRIGHT + "\nFinal: %s\n" % candidates[k])
					exit(0)
		cipher = candidates
