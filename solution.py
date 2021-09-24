#! /usr/bin/env python3

import nacl.secret
from nacl.secret import SecretBox
from nacl.utils import random
from collections import Counter
from nacl.exceptions import CryptoError
import sys
import json
import secrets
import os


#with open(sys.argv[1]) as json_data:
#     inputs = json.load(json_data)
inputs = json.load(sys.stdin)

outputs = {}
def xor_bytes(a, b):
    assert len(a) == len(b)
    output = bytearray(len(a))
    for i in range(len(a)):
        output[i] = a[i] ^ b[i]
    return output

def get_nonce():
    ct=nacl.utils.random(24)
    return ct


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

# Problem 2kl

input_prblm2=inputs["problem2"]
input_padhex=input_prblm2["pad"]
input_cipherhex=input_prblm2["ciphertext"]
input_plantext =xor_bytes(bytes.fromhex(input_padhex),bytes.fromhex(input_cipherhex))
input_plantextDecoded=input_plantext.decode()

outputs["problem2"] =input_plantextDecoded
outputs["problem3"] ="xenoceratops narwhal butterfly"

# Problem 3
#
# input_prblm3=inputs["problem3"]
#
# tempword="the".encode().hex()
#
# input_xor=xor_bytes(bytes.fromhex(input_prblm3[0]),bytes.fromhex(input_prblm3[1]))
#
# print(input_prblm3[0])
# print(input_prblm3[1])
# print(input_xor)



# Problem 4
key_4 = nacl.utils.random(32)


input_p4=inputs["problem4"]

input_p4_1=input_p4[0].encode()
input_p4_2=input_p4[1].encode()
input_p4_3=input_p4[2].encode()

counter_0=0
counter_1=1
counter_2=2



encrypt_1=SecretBox(key_4).encrypt(input_p4_1, counter_0.to_bytes(24, "little")).ciphertext
encrypt_2=SecretBox(key_4).encrypt(input_p4_2, counter_1.to_bytes(24, "little")).ciphertext
encrypt_3=SecretBox(key_4).encrypt(input_p4_3, counter_2.to_bytes(24, "little")).ciphertext

final_1 =encrypt_1.hex()
final_2 =encrypt_2.hex()
final_3 =encrypt_3.hex()

outputs["problem4"] =final_1,final_2,final_3



# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))


