import pytest
from src.detego.automation import Identify, Check

#@pytest.fixture
def dic_file():
	with open("dictionary.txt", 'r') as file:
		dictionary = file.read()
		dictionary = dictionary.split('\n')
	return dictionary

@pytest.mark.parametrize("cipher, plain", [
    ("VGhpcyB0ZXN0IGlzIGEgc2ltcGxlIGJhc2U2NA==", "This test is a simple base64"),
    ("54 68 69 73 20 74 65 73 74 20 69 73 20 61 20 73 69 6d 70 6c 65 20 68 65 78 61 64 65 63 69 6d 61 6c", "This test is a simple hexadecimal"),
    ("Guvf grfg vf n fvzcyr ebg13!", "This test is a simple rot13!"),
    ("Rfgq rcqr gq y qgknjc pmr24!", "This test is a simple rot24!"),
    ("- .... .. .../- . ... -/.. .../.-/... .. -- .--. .-.. ./-- --- .-. ... ./-.-. --- -.. .", "THIS TEST IS A SIMPLE MORSE CODE"),
    ("01010100 01101000 01101001 01110011 00100000 01110100 01100101 01110011 01110100 00100000 01101001 01110011 00100000 01100001 00100000 01110011 01101001 01101101 01110000 01101100 01100101 00100000 01100010 01101001 01101110 01100001 01110010 01111001", "This test is a simple binary"),
    ("RHJzYyBkb2NkIGVjb2MgZGd5IHNkb2JrZHN5eGM6IGJ5ZDEwIGt4biBsa2NvNjQ=", "This test uses two iterations: rot10 and base64"),
    ("0x2d0x200x2e0x2e0x2e0x2e0x200x2e0x2e0x200x2e0x2e0x2e0x0a0x2d0x200x2e0x200x2e0x2e0x2e0x200x2d0x0a0x2e0x2e0x2d0x200x2e0x2e0x2e0x200x2e0x200x2e0x2e0x2e0x0a0x2d0x200x2e0x2d0x2d0x200x2d0x2d0x2d0x0a0x2e0x2e0x200x2d0x200x2e0x200x2e0x2d0x2e0x200x2e0x2d0x200x2d0x200x2e0x2e0x200x2d0x2d0x2d0x200x2d0x2e0x200x2e0x2e0x2e0x200x2d0x2d0x2d0x2e0x2e0x2e0x0a0x2d0x2d0x200x2d0x2d0x2d0x200x2e0x2d0x2e0x200x2e0x2e0x2e0x200x2e0x0a0x2e0x2d0x200x2d0x2e0x200x2d0x2e0x2e0x0a0x2e0x2e0x2e0x2e0x200x2e0x200x2d0x2e0x2e0x2d", "THIS TEST USES TWO ITERATIONS: MORSE AND HEX"),
    ("01001110,01100010,01100011,01101101,00100000,01101110,01111001,01101101,01101110,00100000,01101111,01101101,01111001,01101101,00100000,01101110,01110001,01101001,00100000,01100011,01101110,01111001,01101100,01110101,01101110,01100011,01101001,01101000,01101101,00111010,00100000,01101100,01101001,01101110,00110010,00110000,00100000,01110101,01101000,01111000,00100000,01110110,01100011,01101000,01110101,01101100,01110011", "This test uses two iterations: rot20 and binary"),
    ("MDEwMDExMTA6MDExMDAwMTA6MDExMDAwMTE6MDExMDExMDE6MDAxMDAwMDA6MDExMDExMTA6MDExMTEwMDE6MDExMDExMDE6MDExMDExMTA6MDAxMDAwMDA6MDExMDExMTE6MDExMDExMDE6MDExMTEwMDE6MDExMDExMDE6MDAxMDAwMDA6MDExMDExMTA6MDExMDAwMTA6MDExMDExMDA6MDExMTEwMDE6MDExMTEwMDE6MDAxMDAwMDA6MDExMDAwMTE6MDExMDExMTA6MDExMTEwMDE6MDExMDExMDA6MDExMTAxMDE6MDExMDExMTA6MDExMDAwMTE6MDExMDEwMDE6MDExMDEwMDA6MDExMDExMDE6MDAxMTEwMTA6MDAxMDAwMDA6MDExMDExMDA6MDExMDEwMDE6MDExMDExMTA6MDAxMTEwMDE6MDAxMDExMDA6MDAxMDAwMDA6MDExMTAxMTA6MDExMDAwMTE6MDExMDEwMDA6MDExMTAxMDE6MDExMDExMDA6MDExMTAwMTE6MDAxMDExMDA6MDAxMDAwMDA6MDExMTAxMTA6MDExMTAxMDE6MDExMDExMDE6MDExMTEwMDE6MDAxMTAxMTA6MDAxMTAxMDA=", "This test uses three iterations: rot9, binary, base64"),
    ("....- --...  --... .....  --... -....  -.... -....  ..--- -----  -.... --...  --... ..---  -.... -....  -.... --...  ..--- -----  -.... ---..  -.... -....  --... ..---  -.... -....  ..--- -----  -.... --...  --... .....  -.... .....  --... ..---  --... ..---  ..--- -----  --... -....  -.... --...  --... ..---  -.... .....  -.... .  -.... --...  --... -....  -.... ..---  -.... .----  -.... -....  ...-- .-  ..--- -----  -.... .....  -.... ..---  -.... --...  ...-- .----  ...-- ...--  ..--- -.-.  ..--- -----  --... .....  --... ..---  -.... -...  ..--- -.-.  ..--- -----  --... .-  -.... ..---  -.... .....  -.... -....  --... ..---", "This test uses three iterations: rot13, hex, morse"),
])
@pytest.mark.parametrize("dictionary, search", [
    (dic_file(), None),
    (None, "test")
])


def test_identify_decode_check(cipher, plain, dictionary, search):
    for i in range(1,3): # runs three iterations
        print("Iteration %d:" % i)
        verbose = i
        candidates = Identify.main(cipher, verbose)
        for candidate in candidates:
            if Check(candidate, search, dictionary, 3):
                final = candidate
                print("\nFinal: %s\n" % final)
                assert final == plain
                return final
            else:
                final = 'Not found'
