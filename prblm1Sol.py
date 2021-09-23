# ! /usr/bin/env python3

from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
import sys
import json

## with open(sys.argv[1]) as json_data:
##    inputs = json.load(json_data)
##
inputs = json.load(sys.stdin)

outputs = {}

# Problem 1
ints_sum = 0
ints_product = 1
for x in inputs["problem1"]:
    ints_sum += x
    ints_product *= x
outputs["problem1"] = {
    "sum": ints_sum,
    "product": ints_product,
}

# Problem 2

input_hexstr=inputs["problem2"]
output_byte=bytes.fromhex(input_hexstr)

output_str=output_byte.decode()
outputs["problem2"]= output_str

# Problem 3

input_str=inputs["problem3"]
output_bytes=input_str.encode()

output_hex=output_bytes.hex()
outputs["problem3"]= output_hex

# Problem 4

in_cyper_hex=inputs["problem4"]
ciphertext_bytes = bytes.fromhex(in_cyper_hex)
key = b"A" * 32
nonce = b"B" * 24
plaintext_bytes = SecretBox(key).decrypt(ciphertext_bytes, nonce)
plaintext_string = plaintext_bytes.decode()
outputs["problem4"] = plaintext_string

# Problem 5
ciphertext_list = inputs["problem5"]
key = b"C" * 32
nonce = b"D" * 24
for ciphertext_hex in ciphertext_list:
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    try:
        plaintext_bytes = SecretBox(key).decrypt(ciphertext_bytes, nonce)
    except CryptoError:
        # Bad ciphertext
        continue
    plaintext_string = plaintext_bytes.decode()
    outputs["problem5"] = plaintext_string
    break


# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))