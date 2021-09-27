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

# with open(sys.argv[1]) as json_data:
#    inputs = json.load(json_data)
inputs = json.load(sys.stdin)

outputs = {}


def xor_bytes(a, b):
    assert len(a) == len(b)
    output = bytearray(len(a))
    for i in range(len(a)):
        output[i] = a[i] ^ b[i]
    return output


def get_nonce():
    ct = nacl.utils.random(24)
    return ct


# Problem 1
input_asciistr = inputs["problem1"]
input_bytes = input_asciistr.encode()
input_asciistr_ln = len(input_bytes)
input_OTP = secrets.token_bytes(input_asciistr_ln)
input_cipher = xor_bytes(input_bytes, input_OTP)

outputs["problem1"] = {
    "pad": input_OTP.hex(),
    "ciphertext": input_cipher.hex(),
}

# Problem 2

input_prblm2 = inputs["problem2"]
input_padhex = input_prblm2["pad"]
input_cipherhex = input_prblm2["ciphertext"]
input_plantext = xor_bytes(bytes.fromhex(input_padhex), bytes.fromhex(input_cipherhex))
input_plantextDecoded = input_plantext.decode()

outputs["problem2"] = input_plantextDecoded

# # Problem 3
#
input_prblm3 = inputs["problem3"]

charLen = len(input_prblm3[0])

plaintext = ""
for i in range(len(bytes.fromhex(input_prblm3[0]))):
    plaintext = plaintext + "$"
    # print(plaintext)

plainTextHex = plaintext.encode().hex()

onetime_pad = xor_bytes(bytes.fromhex(plainTextHex), bytes.fromhex(input_prblm3[0]))

second_plainText = xor_bytes(onetime_pad, bytes.fromhex(input_prblm3[1]))

outputs["problem3"] = second_plainText.decode()

# # # Problem 4
key_4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".encode()
input_p4=inputs["problem4"]
cnt=0
final_1=[]
for x in input_p4:
    newcnt=cnt.to_bytes(24, "little")
    encrypt_1 = SecretBox(key_4).encrypt(x.encode(), newcnt).ciphertext
    final_1.append(encrypt_1.hex())
    cnt += 1
outputs["problem4"]=final_1

# # # Problem 5
key_5 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".encode()
input_p5=inputs["problem5"]
cnt=0
final_5=[]
for x in input_p5:
    newcnt_5=cnt.to_bytes(24, "little")
    encrypt_5 = SecretBox(key_5).decrypt(bytes.fromhex(x), newcnt_5)
    final_5.append(encrypt_5.decode())
    cnt += 1
outputs["problem5"]=final_5



# # Problem 6

input_prblm6 = inputs["problem6"]

charLen = len(input_prblm6[0])

plaintext_6 = ""
for i in range(len(bytes.fromhex(input_prblm6[0]))):
    plaintext_6 = plaintext_6 + "$"
    # print(plaintext)

plainTextHex_6 = plaintext_6.encode().hex()

onetime_pad_6 = xor_bytes(bytes.fromhex(plainTextHex_6), bytes.fromhex(input_prblm6[0]))

second_plainText_6 = xor_bytes(onetime_pad_6, bytes.fromhex(input_prblm6[1]))

sliced=second_plainText_6[16:]

outputs["problem6"] = sliced.decode()



# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))
