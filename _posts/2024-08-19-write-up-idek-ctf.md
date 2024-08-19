---
layout: post
title: Write up IDEK CTF
description: Easy Crypto Challenge
date: '2024-08-19 23:05:13 +0700'
categories: [Write-up]
tags: [crypto]
math: true
mermaid: true
---
## Golden Ticket:
### Source:
Can you help Charles - who doesn't have any knowledge about cryptography, get the golden ticket and have a trip to Willy Wonka's factory ?

```python
from Crypto.Util.number import *

#Some magic from Willy Wonka
def chocolate_generator(m:int) -> int:
    p = 396430433566694153228963024068183195900644000015629930982017434859080008533624204265038366113052353086248115602503012179807206251960510130759852727353283868788493357310003786807
    return (pow(13, m, p) + pow(37, m, p)) % p

#The golden ticket is hiding inside chocolate
flag = b"idek{REDACTED}"
golden_ticket = bytes_to_long(flag)
flag_chocolate = chocolate_generator(golden_ticket)
chocolate_bag = []

#Willy Wonka is making chocolates
for i in range(golden_ticket):
    chocolate_bag.append(chocolate_generator(i))

#And he put the golden ticket at the end
chocolate_bag.append(flag_chocolate)

#Augustus ate lots of chocolates, but he can't eat all cuz he is full now :D
remain = chocolate_bag[-2:]

#Can you help Charles get the golden ticket?
print(remain)

#[88952575866827947965983024351948428571644045481852955585307229868427303211803239917835211249629755846575548754617810635567272526061976590304647326424871380247801316189016325247, 67077340815509559968966395605991498895734870241569147039932716484176494534953008553337442440573747593113271897771706973941604973691227887232994456813209749283078720189994152242]

```

### Solutions:
From the source, we can see that flag_chocolate is constructed by: $13^m+37^m \; \% \; p$. The last 2 flag_chocolate will have relation:

$$a = 13^{m-1} + 37^{m-1}\; \%  \;p$$

$$b = 13^{m} + 37^{m} \; \% \;  p$$


$$13^{m-1} = (1) \cdot (37-13)^{-1}$$

with all number in $Zmod(p)$. We notice that p-1 is smooth so apply Pohlig-Hellman to find m-1.

```python
p = 396430433566694153228963024068183195900644000015629930982017434859080008533624204265038366113052353086248115602503012179807206251960510130759852727353283868788493357310003786807
a = 88952575866827947965983024351948428571644045481852955585307229868427303211803239917835211249629755846575548754617810635567272526061976590304647326424871380247801316189016325247
b = 67077340815509559968966395605991498895734870241569147039932716484176494534953008553337442440573747593113271897771706973941604973691227887232994456813209749283078720189994152242

tmp = (a*37 - b)%p
tmp  = tmp * inverse_mod(37-13,p)%p

K = GF(p)
zz = K(13)
tmp = K(tmp)
flag = tmp.log(zz)+1
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(int(flag)))
#idek{charles_and_the_chocolate_factory!!!}
```

## Baby Bundle:
### Source:
A crane flew by, and delivered this baby chall. I can't understand a word it speaks.
```python
# Patch deprecation warnings
sage.structure.element.is_Matrix = lambda z: isinstance(z, sage.structure.element.Matrix)
# See README.md for this package
from vector_bundle import *
from string import printable
from tqdm import tqdm

password = ''.join(choice(printable) for _ in range(15)).encode()

p = 66036476783091383193200018291948785097
F = GF(p)
K.<x> = FunctionField(F)
L = VectorBundle(K, -x.zeros()[0].divisor()) # L = O(-1)

V = L.tensor_power(password[0])
for b in tqdm(password[1:]):
    V = V.direct_sum(L.tensor_power(b))

L = L.dual() # L = O(1)
out = [
    len(V.tensor_product(L.tensor_power(m)).h0())
    for m in tqdm(printable.encode())
]

print(out)


from Crypto.Cipher import AES
from hashlib import sha256
from flag import flag
flag += bytes((16-len(flag)) % 16)

key = sha256(bytes(sorted(password))).digest()[:16]
aes = AES.new(key, AES.MODE_ECB)
enc = aes.encrypt(flag)
print('enc:', enc.hex())
```
### Solution:
After some conversation with chatGPT, i know some important facts about the algorithm 🥳, but know understand all the math behind.
```python
p = 66036476783091383193200018291948785097
F = GF(p)
K.<x> = FunctionField(F)
L = VectorBundle(K, -x.zeros()[0].divisor()) # L = O(-1)

V = L.tensor_power(password[0])
for b in tqdm(password[1:]):
    V = V.direct_sum(L.tensor_power(b))

L = L.dual() # L = O(1)
out = [
    len(V.tensor_product(L.tensor_power(m)).h0())
    for m in tqdm(printable.encode())
]

print(out)
```
Each element in $out$ array present for a sum of all:
```python
V.tensor_product(L.tensor_power(m)).h0()
```
This function will calculate - very simple as. First take $m$ from printable - array. And compare it will the password char.

* If m - password[i] >= 0 then adding to the sum m-password[i]+1
* Else adding 0.
  
Derive from that knowledge. I have write the script to solve the challenge.

```python
from string import printable
from tqdm import tqdm
out = [49, 52, 55, 58, 62, 66, 71, 76, 81, 86, 431, 444, 457, 470, 484, 498, 512, 526, 540, 554, 568, 582, 596, 610, 625, 640, 655, 670, 685, 700, 715, 730, 745, 760, 775, 790, 134, 141, 148, 155, 162, 169, 176, 184, 192, 200, 208, 216, 224, 232, 240, 248, 257, 266, 275, 284, 293, 303, 313, 323, 333, 345, 24, 25, 26, 27, 28, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 91, 96, 101, 106, 113, 120, 127, 357, 369, 381, 393, 405, 418, 805, 820, 835, 850, 23, 0, 1, 4, 2, 3]
array = []
for (i,j) in zip(printable.encode(), out):
    array.append((i,j))
    
sorted_array = sorted(array, key=lambda x: x[1])
password = []
for zz in sorted_array:
    cur_char, value = zz
    if value == 0:
        continue
    if value == 1:
        password.append(cur_char)
        continue
    calculate = cur_char*len(password) - sum(password) + 1*len(password)
    if calculate == value:
        continue
    if calculate !=value:
        re_calculate = calculate
        while re_calculate != value:
            password.append(cur_char)
            re_calculate = cur_char*len(password) - sum(password) + 1*len(password)
            
password = [chr(k) for k in password]
password = ''.join(password)
password = password.encode()

print(password)
from Crypto.Cipher import AES
from hashlib import sha256
ct = '5f0a8761f98748422d97f60f11d8590d56e1462409a677fbf52259b084b8a724'
ct = bytes.fromhex(ct)
key = sha256(password).digest()[:16]
aes = AES.new(key, AES.MODE_ECB)
msg = aes.decrypt(ct)
print(msg)
#idek{R34dy_f0r_m0r3?}
```