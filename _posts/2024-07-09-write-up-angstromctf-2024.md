---
layout: post
title: Write-up-Angstromctf-2024
date: '2024-05-29 07:43:17 +0700'
description: Crypto challenges
categories: [WriteUps]
tags: [crypto]
math: true
mermaid: true
---


## PHIlosophy
### Challenge decription:
Clam decided to start studying philosophy, and what is the difference between plus one and minus one anyway...

```python
from Crypto.Util.number import getPrime
from secret import flag

p = getPrime(512)
q = getPrime(512)

m = int.from_bytes(flag.encode(), "big")

n = p * q
e = 65537
c = pow(m, e, n)

phi = (p + 1) * (q + 1)

print(f"n: {n}")
print(f"e: {e}")
print(f"c: {c}")
print(f"\"phi\": {phi}")

"""
n: 86088719452932625928188797700212036385645851492281481088289877829109110203124545852827976798704364393182426900932380436551569867036871171400190786913084554536903236375579771401257801115918586590639686117179685431627540567894983403579070366895343181435791515535593260495162656111028487919107927692512155290673
e: 65537
c: 64457111821105649174362298452450091137161142479679349324820456191542295609033025036769398863050668733308827861582321665479620448998471034645792165920115009947792955402994892700435507896792829140545387740663865218579313148804819896796193817727423074201660305082597780007494535370991899386707740199516316196758
"phi": 86088719452932625928188797700212036385645851492281481088289877829109110203124545852827976798704364393182426900932380436551569867036871171400190786913084573410416063246853198167436938724585247461433706053188624379514833802770205501907568228388536548010385588837258085711058519777393945044905741975952241886308
"""
```

### Solution:
We notice that the phi is different from ordinary $phi = (p-1)*(p-1)$. But after some calculation, we will have $S=p+q$ and $P = pq$. Apply viete theorem and we will receive p,q.
```python
n=86088719452932625928188797700212036385645851492281481088289877829109110203124545852827976798704364393182426900932380436551569867036871171400190786913084554536903236375579771401257801115918586590639686117179685431627540567894983403579070366895343181435791515535593260495162656111028487919107927692512155290673
e=65537
c=64457111821105649174362298452450091137161142479679349324820456191542295609033025036769398863050668733308827861582321665479620448998471034645792165920115009947792955402994892700435507896792829140545387740663865218579313148804819896796193817727423074201660305082597780007494535370991899386707740199516316196758
phi = 86088719452932625928188797700212036385645851492281481088289877829109110203124545852827976798704364393182426900932380436551569867036871171400190786913084573410416063246853198167436938724585247461433706053188624379514833802770205501907568228388536548010385588837258085711058519777393945044905741975952241886308
# phi = (p+1)*(q+1)

# phi = p*q + p + q + 1
# phi = n + p + q + 1

pq = phi - n - 1
a = 1
b = pq
c = n
print(a,b,c)
var('x')
quadratic_eq = a*x^2 -b*x + c

# Solve the quadratic equation
solutions = quadratic_eq.roots()
print(solutions)
#actf{its_okay_i_figured_out_phi_anyway}
```

## layers
### Challenge decription:
```python
import hashlib
import itertools
import os

def xor(key, data):
    return bytes([k ^ d for k, d in zip(itertools.cycle(key), data)])

def encrypt(phrase, message, iters=1000):
    key = phrase.encode()
    for _ in range(iters):
        key = hashlib.md5(key).digest()
        message = xor(key, message)
    return message

print('Welcome to my encryption service!')
print('Surely encrypting multiple times will make it more secure.')
print('1. Encrypt message.')
print('2. Encrypt (hex) message.')
print('3. See encrypted flag!')

phrase = os.environ.get('FLAG', 'missing')

choice = input('Pick 1, 2, or 3 > ')
if choice == '1':
    message = input('Your message > ').encode()
    encrypted = encrypt(phrase, message)
    print(encrypted.hex())
if choice == '2':
    message = bytes.fromhex(input('Your message > '))
    encrypted = encrypt(phrase, message)
    print(encrypted.hex())
elif choice == '3':
    print(encrypt(phrase, phrase.encode()).hex())
else:
    print('Not sure what that means.')

```
### Solution:
We can see this a xor encryption, and the key is xored 1000 times with the message:
$msg = msg \oplus key .. \oplus \, key$ (1000 times):
If we sent null bytes, we will receive the key xor with itself 1000 times, xor that back to the ciphertext and then we have reconverd the message.
```python
from pwn import *
import itertools
conn = remote('challs.actf.co', 31398)    
def xor(key, data):
    return bytes([k ^ d for k, d in zip(itertools.cycle(key), data)])

en_flag = 'fb7fdbf9e714a08ce9cdf109bb527acba27accfeff16fcdcb1cdf358bb557898aa2d9da9af5c'
en_flag = bytes.fromhex(en_flag)
t = len(en_flag)
conn.recvuntil('> ')
conn.sendline('1')

payload  = b'\x00'*t
conn.sendline(payload)

conn.recvuntil('Your message > ')
rev = conn.recvline().strip()
rev = bytes.fromhex(rev.decode())

msg = xor(rev, en_flag)
print(msg)
#actf{593a7043ca58fcac7ec972e3dcf01263}
```
## random rabin
### Challenge decription:
I heard that the Rabin cryptosystem has four decryptions per ciphertext. So why not choose one randomly?

```python
from random import SystemRandom
from Crypto.Util.number import getPrime
from libnum import xgcd

random = SystemRandom()

def primegen():
	while True:
		p = getPrime(512)
		if p % 4 == 3:
			return p

def keygen():
	p = primegen()
	q = primegen()
	n = p * q
	return n, (n, p, q)

def encrypt(pk, m):
	n = pk
	return pow(m, 2, n)

def decrypt(sk, c):
	n, p, q = sk
	yp, yq, _ = xgcd(p, q) 
	mp = pow(c, (p + 1)//4, p) 
	mq = pow(c, (q + 1)//4, q)
	s = yp * p * mq % n
	t = yq * q * mp % n
	rs = [(s + t) % n, (-s - t) % n, (s - t) % n, (-s + t) % n] 
	r = random.choice(rs)
	return r

def game(): 
	pk, sk = keygen()
	print(f'pubkey: {pk}')
	secret = random.randbytes(16)
	m = int.from_bytes(secret, 'big')
	print(f'plaintext: {decrypt(sk, encrypt(pk, m))}')
	guess = bytes.fromhex(input('gimme the secret: '))
	return guess == secret

if __name__ == '__main__':
	for _ in range(64):
		success = game()
		if not success:
			exit()

	with open('flag.txt') as f:
		flag = f.read().strip()
		print(flag)

```
### Solution:
The Rabin cryptosystem derive on the quadractic residue to encrypt, and decrypt message.
We notice that in the decrypt process it will pick one of 4 and return it out. We don't know what form of the number we receive but one of its property: $r^2 \equiv ct \pmod{n}$ and $ct \equiv m^2 \pmod{n}$. The message is only 16 bytes so it can not larger than modulo n with is 1024 bit.
```python
from pwn import *
from gmpy2 import iroot
def calculate(n, m):
    m = (m + n) % n
    c = (m * m) % n
    p = iroot(c, 2)[0]
    hex_p = hex(p)[2:]
    hex_p = hex_p.zfill(32)
    return hex_p
count = 0
conn = remote('challs.actf.co',31300)
while True:
    conn.recvuntil('pubkey: ')
    n = int(conn.recvline().decode().strip())
    conn.recvuntil('plaintext: ')
    m = int(conn.recvline().decode().strip())
    conn.recvuntil('gimme the secret: ')
    print(f'{count}th round')
    payload = calculate(n,m)
    print(f'answer:{payload}')
    conn.sendline(payload.strip())

    count += 1
    if count == 64:
        print(conn.recvall())
        break
    sleep(0.5)
#actf{f4ncy_squ4re_r00ts_53a370c33f192973}
```
## tss1
### Challenge decription:
I implemented a simple threshold signature scheme for Schnorr signatures.
```python
from hashlib import sha256
import fastecdsa.curve
import fastecdsa.keys
import fastecdsa.point

TARGET = b'flag'

curve = fastecdsa.curve.secp256k1

def input_point():
	x = int(input('x: '))
	y = int(input('y: '))
	return fastecdsa.point.Point(x, y, curve=curve)

def input_sig():
	c = int(input('c: '))
	s = int(input('s: '))
	return (c, s)

def hash_transcript(pk, R, msg):
	h = sha256()
	h.update(f'({pk.x},{pk.y})'.encode())
	h.update(f'({R.x},{R.y})'.encode())
	h.update(msg)
	return int.from_bytes(h.digest(), 'big') % curve.q

def verify(pk, msg, sig):
	c, s = sig
	R = s * curve.G + c * pk
	return c == hash_transcript(pk, R, msg)

if __name__ == '__main__':
	import sys

	if len(sys.argv) == 2 and sys.argv[1] == 'setup':
		sk1, pk1 = fastecdsa.keys.gen_keypair(curve)
		with open('key.txt', 'w') as f:
			f.write(f'{sk1}\n{pk1.x}\n{pk1.y}\n')
		exit()

	with open('key.txt') as f:
		sk1, x, y = map(int, f.readlines())
		pk1 = fastecdsa.point.Point(x, y, curve=curve)

	print(f'my public key: {(pk1.x, pk1.y)}')

	print('gimme your public key')
	pk2 = input_point()

	apk = pk1 + pk2
	print(f'aggregate public key: {(apk.x, apk.y)}')

	print('what message do you want to sign?')
	msg = bytes.fromhex(input('message: '))
	if msg == TARGET:
		print('anything but that')
		exit()

	k1, R1 = fastecdsa.keys.gen_keypair(curve)
	print(f'my nonce: {(R1.x, R1.y)}')

	print(f'gimme your nonce')
	R2 = input_point()

	R = R1 + R2
	print(f'aggregate nonce: {(R.x, R.y)}')

	c = hash_transcript(apk, R, msg)
	s = (k1 - c * sk1) % curve.q
	print(f'my share of the signature: {s}')
	print(k1)

	print(f'gimme me the aggregate signature for "{TARGET}"')
	sig = input_sig()
	if verify(apk, TARGET, sig):
		with open('flag.txt') as f:
			flag = f.read().strip()
			print(flag)

```
### Solution:
The main idea is to make $apk$ and $R$ is determined. The easiy way to get it is to get $pk2$ and $R2$ (which we can calulate) to $-pk1+G$ and $-R1+G$ respectively. This will make $apk$ and $R$ is G -  which we know, the rest is just some implementation.
```python
from pwn import*
from hashlib import sha256
import fastecdsa.curve
import fastecdsa.keys
import fastecdsa.point
TARGET = b'flag'
curve = fastecdsa.curve.secp256k1

conn = remote('challs.actf.co', 31301)

conn.recvuntil(b'public key: ')
x,y = conn.recvline().strip().split(b',')
x = int(x[1:])
y = int(y[:-1])
print(x,y)
pk = fastecdsa.point.Point(x, y, curve=curve)
t = pk - curve.G
payload_x = int(t.x)
payload_y = -int(t.y)
conn.recvuntil(b'x: ')
conn.sendline(str(payload_x))
conn.recvuntil(b'y: ')
conn.sendline(str(payload_y))
print(conn.recvline())
print(conn.recvline())
conn.recvuntil(b'message: ')
conn.sendline(' ')
conn.recvuntil(b'my nonce: ')
x2,y2 = conn.recvline().strip().split(b',')
x2 = int(x2[1:])
y2 = int(y2[:-1])
R = fastecdsa.point.Point(x2, y2, curve=curve)
t2 = R - curve.G
payload_x2 = int(t2.x)
payload_y2 = -int(t2.y)
conn.recvuntil(b'x: ')
conn.sendline(str(payload_x2))
conn.recvuntil(b'y: ')
conn.sendline(str(payload_y2))
conn.recvuntil(b'c: ')
c = 29689281256975185254987441207265069040127336078857920796443223575336925266032
s = -(c-1)
conn.sendline(str(c))
conn.recvuntil(b's: ')
conn.sendline(str(s))
conn.interactive()
```