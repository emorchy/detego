import pytest
import tqdm
from src.automation import *

@pytest.mark.parametrize("cipher, plain", [
    ("VGhpcyB0ZXN0IGlzIGEgc2ltcGxlIGJhc2U2NA==", "This test is a simple base64"),
    ("54 68 69 73 20 74 65 73 74 20 69 73 20 61 20 73 69 6d 70 6c 65 20 68 65 78 61 64 65 63 69 6d 61 6c", "This test is a simple hexadecimal"),
    ("Guvf grfg vf n fvzcyr ebg46", "This test is a simple rot13"),
    ("- .... .. .../- . ... -/.. .../.-/... .. -- .--. .-.. ./-- --- .-. ... ./-.-. --- -.. .", "THIS TEST IS A SIMPLE MORSE CODE"),
    ("01010100 01101000 01101001 01110011 00100000 01110100 01100101 01110011 01110100 00100000 01101001 01110011 00100000 01100001 00100000 01110011 01101001 01101101 01110000 01101100 01100101 00100000 01100010 01101001 01101110 01100001 01110010 01111001", "This test is a simple binary"),
])
@pytest.mark.parametrize("dictionary, search", [
    ("dictionary.txt", None),
    (None, "test")
])

#@pytest.fixture
#def num():
#	num = 4
#	return num

def test_identify_decode_check(cipher, plain, dictionary, search):
	candidates = Identify.main(cipher)
	#for i in range(1,3): # runs three iterations
	#print("Iteration %d:" % i)
	candidates = Identify.main(cipher)
	print("Candidates %s, cipher %s" % (candidates, cipher))
	for k in range(len(candidates)):
		if Check(candidates[k]):
			final = candidates[k]
			break
		else:
			final = 'Not found'
	print(Fore.RED + Style.BRIGHT + "\nFinal: %s\n" % final)
	assert final == plain
