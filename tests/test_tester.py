import pytest
import tqdm
from src.automation import *

@pytest.mark.parametrize("cipher, plain", [
    ("VGhpcyB0ZXN0IGlzIGEgc2ltcGxlIGJhc2U2NA==", "This test is a simple base64"),
    ("54 68 69 73 20 74 65 73 74 20 69 73 20 61 20 73 69 6d 70 6c 65 20 68 65 78 61 64 65 63 69 6d 61 6c", "This test is a simple hexadecimal"),
    ("Guvf grfg vf n fvzcyr ebg46", "This test is a simple rot13"),
    ("- .... .. .../- . ... -/.. .../.-/... .. -- .--. .-.. ./-- --- .-. ... ./-.-. --- -.. .", "This test is a simple morse code"),
    ("01010100 01101000 01101001 01110011 00100000 01110100 01100101 01110011 01110100 00100000 01101001 01110011 00100000 01100001 00100000 01110011 01101001 01101101 01110000 01101100 01100101 00100000 01100010 01101001 01101110 01100001 01110010 01111001", "This test is a simple binary"),
])
def test_identify_decode_check(cipher, plain):
	candidates = Identify(cipher)
	assert plain in candidates
	for i in range(1, 1 + iteration):
		print("Iteration %d:" % i)
		for j in range(len(cipher)):
			candidates = Identify(cipher[j])
			print("Candidates %s, cipher %s" % (candidates, cipher))
			for k in range(len(candidates)):
				if Check(candidates[k]):
						print(Fore.RED + Style.BRIGHT + "\nFinal: %s\n" % candidates[k])
						assert candidates[k] == plain


@pytest.fixture
def cipherfile():
	return None
@pytest.fixture
def dictionary():
	return ["dictionary.txt", None]
@pytest.fixture
def search():
	return (None, "test")
@pytest.fixture
def listuser():
	return [False, True]
@pytest.fixture
def rot():
	return True
@pytest.fixture
def userdefined():
	return None
@pytest.fixture
def number():
	return 3
@pytest.fixture
def iteration():
	return [1,1,2,2,3,3,4,4]
@pytest.fixture
def ciphertext():
	with open("ciphers.txt", 'r') as file:
		ciphertext = []
		for cipher in file:
			ciphertext.append(cipher)
	return ciphertext
@pytest.fixture
def cipherfile():
	return None

def test_main():
	if '__name__' == '__main__':
		for i in range(len(ciphertext("ciphers.txt"))):
			Test(ciphertext()[i], cipherfile(), dictionary()[i % len(dictionary)], search()[i % len(search)], listuser()[0], rot(), userdefined(), number(), iteration()[i % len(iteration)])
