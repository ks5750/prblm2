#! /usr/bin/env python3

from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
import sys
import json
import secrets
import os



##with open(sys.argv[1]) as json_data:
## inputs = json.load(json_data)
inputs = json.load(sys.stdin)

outputs = {}
def xor_bytes(a, b):
    #assert len(a) == len(b)
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


# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))


