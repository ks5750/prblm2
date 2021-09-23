#! /usr/bin/env python3

from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
import sys
import json
import secrets
import os



with open(sys.argv[1]) as json_data:
    inputs = json.load(json_data)
## inputs = json.load(sys.stdin)

outputs = {}
def xor_bytes(a, b):
    assert len(a) == len(b)
    output = bytearray(len(a))
    for i in range(len(a)):
        output[i] = a[i] ^ b[i]
    return output

# Problem 1
input_asciistr=inputs["problem1"]
input_bytes=input_asciistr.encode()
input_asciistr_ln=len(input_bytes)
input_OTP=secrets.token_bytes(input_asciistr_ln)
input_cipher =xor_bytes(input_bytes,input_OTP)

outputs["problem1"] = {
    "pad": input_OTP.hex(),
    "ciphertext": input_cipher.hex(),
}

# Problem 2

input_prblm2=inputs["problem2"]
input_padhex=input_prblm2["pad"]
input_cipherhex=input_prblm2["ciphertext"]
input_plantext =xor_bytes(bytes.fromhex(input_padhex),bytes.fromhex(input_cipherhex))
input_plantextDecoded=input_plantext.decode()

outputs["problem2"] =input_plantextDecoded

# Problem 3

input_prblm3=inputs["problem3"]

tempword="the".encode().hex()

input_xor=xor_bytes(bytes.fromhex(input_prblm3[0]),bytes.fromhex(input_prblm3[1]))

print(input_prblm3[0])
print(input_prblm3[1])
print(input_xor)


# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))


