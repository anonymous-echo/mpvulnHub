#  密码学赛题复现：2021-CryptoCTF（二）   
原创 核心基础实验室  山石网科安全技术研究院   2022-08-11 10:30  
  
```
Crypto CTF is an online competition for hackers to test, evaluate, and expand their cryptography exploiting skills. In this CTF, we will provide various crypto challenges regarding modern cryptography techniques.
All crypto lovers are most welcome!
Crypto CTF is a revenge for everlasting complaints by CTF participants about crypto challenges in CTF contests. In this brand-new tournament, we are trying to provide the crypto lovers with fun and challenging pure crypto tasks to squeeze their heart and test their passion for cryptography.
Each task will be based on a particular cryptographic primitive, or it will include a direct application of cryptography in other fields.
The organizers of these tournaments generously offer their skills' knowledge to design original Crypto tasks and challenges for similar contests.Long Live Crypto :)
```  
  
续上续上…  
- ## Triplet  
  
POINTS：91  
  
考点：RSA，欧拉函数  
```
#!/usr/bin/env python3

from Crypto.Util.number import *
from random import randint
import sys
flag='a'*55

def die(*args):
 pr(*args)
 quit()

def pr(*args):
 s = " ".join(map(str, args))
 sys.stdout.write(s + "\n")
 sys.stdout.flush()

def sc():
 return sys.stdin.readline().strip()

def main():
 border = "+"
 pr(border*72)
 pr(border, " hi talented cryptographers, the mission is to find the three RSA   ", border)
 pr(border, " modulus with the same public and private exponent! Try your chance!", border)
 pr(border*72)

 nbit = 160

 while True:
  pr("| Options: \n|\t[S]end the three nbit prime pairs \n|\t[Q]uit")
  ans = sc().lower()
  order = ['first', 'second', 'third']
  if ans == 's':
   P, N = [], []
   for i in range(3):
    pr("| Send the " + order[i] + " RSA primes such that nbit >= " + str(nbit) + ": p_" + str(i+1) + ", q_" + str(i+1) + " ")
    params = sc()
    try:
     p, q = params.split(',')
     p, q = int(p), int(q)
    except:
     die("| your primes are not valid!!")
    if isPrime(p) and isPrime(q) and len(bin(p)[2:]) >= nbit and len(bin(q)[2:]) >= nbit:
     P.append((p, q))
     n = p * q
     N.append(n)
    else:
     die("| your input is not desired prime, Bye!")
   if len(set(N)) == 3:
    pr("| Send the public and private exponent: e, d ")
    params = sc()
    try:
     e, d = params.split(',')
     e, d = int(e), int(d)
    except:
     die("| your parameters are not valid!! Bye!!!")
    phi_1 = (P[0][0] - 1)*(P[0][1] - 1)
    phi_2 = (P[1][0] - 1)*(P[1][1] - 1)
    phi_3 = (P[2][0] - 1)*(P[2][1] - 1)
    if 1 < e < min([phi_1, phi_2, phi_3]) and 1 < d < min([phi_1, phi_2, phi_3]):
     b = (e * d % phi_1 == 1) and (e * d % phi_2 == 1) and (e * d % phi_3 == 1)
     if b:
      die("| You got the flag:", FLAG)
     else:
      die("| invalid exponents, bye!!!")
    else:
     die("| the exponents are too small or too large!")
   else:
    die("| kidding me?!!, bye!")
  elif ans == 'q':
   die("Quitting ...")
  else:
   die("Bye ...")

if __name__ == '__main__':
 main()

```  
  
可以看到题目逻辑很简单，就是让你输入三对 p,q，在同一对 e,d的情况下，均满足  
```
if 1 < e < min([phi_1, phi_2, phi_3]) and 1 < d < min([phi_1, phi_2, phi_3]):
 b = (e * d % phi_1 == 1) and (e * d % phi_2 == 1) and (e * d % phi_3 == 1)

```  
  
满足   
，显然会满足  
  
那么很直观的，我们想要找到一个素数   
，满足   
 也是一个素数，这样  
，就能够满足条件。  
  
同理可以再找一个  
  
最后找一个合适的公钥e，1 < e < min([phi_1, phi_2, phi_3])，然后生成私钥 d = inverse(e，min([phi_1, phi_2, phi_3]))，就能够通过验证，获取flag。  
  
何为合适？能过所有的assert的呗。(因为这里要求d = inverse(e，**min**([phi_1, phi_2, phi_3]))，所以会满足   
 ，但不一定满足  
  
exp.py  
```
from Crypto.Util.number import *
from gmpy2 import is_prime
from tqdm import tqdm
# for _ in tqdm(range(1000)):
#     FLAG=0
#     p = getPrime(170)

#     if is_prime(2*p-1):
#         FLAG+=1
#     if is_prime(4*p-3):
#         FLAG+=1

#     if FLAG >= 2:
#         print(p,2*p-1,4*p-3)
#         break

 #46%|████████████████████████████████████▋                                          | 464/1000 [00:06<00:06, 79.88it/s]1449368757550124595394471100025923300308378816147831 2898737515100249190788942200051846600616757632295661 5797475030200498381577884400103693201233515264591321


q = getPrime(160)
p0 = 1449368757550124595394471100025923300308378816147831
p1 = 2898737515100249190788942200051846600616757632295661
p2 = 5797475030200498381577884400103693201233515264591321

phi1 = (q-1)*(p0-1)
phi2 = (q-1)*(p1-1)
phi3 = (q-1)*(p2-1)
while True:
    e = getPrime(160)
    d = inverse(e,min(phi1,phi2,phi3))
    if e*d % phi1 == 1 and e*d % phi2 == 1 and e*d % phi3 == 1 and 1 < e < min(phi1,phi2,phi3) and 1 < d < min(phi1,phi2,phi3):
        print(e,d)
        break

    
#CCTF{7HrE3_b4Bie5_c4rRi3d_dUr1nG_0Ne_pr39naNcY_Ar3_triplets}

```  
- ## Onlude  
  
POINTS：95  
  
考点：线性代数  
```
#!/usr/bin/env sage

from sage.all import *
from flag import flag

global p, alphabet
p = 71
alphabet = '=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$!?_{}<>'

flag = flag.lstrip('CCTF{').rstrip('}')
assert len(flag) == 24

def cross(m):
    return alphabet.index(m)

def prepare(msg):
    A = zero_matrix(GF(p), 11, 11)
    for k in range(len(msg)):
        i, j = 5*k // 11, 5*k % 11
        A[i, j] = cross(msg[k])
    return A

def keygen():
    R = random_matrix(GF(p), 11, 11)
    while True:
        S = random_matrix(GF(p), 11, 11)
        if S.rank() == 11:
            _, L, U = S.LU()
            return R, L, U

def encrypt(A, key):
    R, L, U = key
    S = L * U
    X = A + R
    Y = S * X
    E = L.inverse() * Y
    return E

A = prepare(flag)
key = keygen()
R, L, U = key
S = L * U
E = encrypt(A, key)
print(f'E = \n{E}')
print(f'L * U * L = \n{L * U * L}')
print(f'L^(-1) * S^2 * L = \n{L.inverse() * S**2 * L}')
print(f'R^(-1) * S^8 = \n{R.inverse() * S**8}')
E = 
[25 55 61 28 11 46 19 50 37  5 21]
[20 57 39  9 25 37 63 31 70 15 47]
[56 31  1  1 50 67 38 14 42 46 14]
[42 54 38 22 19 55  7 18 45 53 39]
[55 26 42 15 48  6 24  4 17 60 64]
[ 1 38 50 10 19 57 26 48  6  4 14]
[13  4 38 54 23 34 54 42 15 56 29]
[26 66  8 48  6 70 44  8 67 68 65]
[56 67 49 61 18 34 53 21  7 48 32]
[15 70 10 34  1 57 70 27 12 33 46]
[25 29 20 21 30 55 63 49 11 36  7]
L * U * L = 
[50  8 21 16 13 33  2 12 35 20 14]
[36 55 36 34 27 28 23 21 62 17  8]
[56 26 49 39 43 30 35 46  0 58 43]
[11 25 25 35 29  0 22 38 53 51 58]
[34 14 69 68  5 32 27  4 27 62 15]
[46 49 36 42 26 12 28 60 54 66 23]
[69 55 30 65 56 13 14 36 26 46 48]
[25 48 16 20 34 57 64 62 61 25 62]
[68 39 11 40 25 11  7 40 24 43 65]
[54 20 40 59 52 60 37 14 32 44  4]
[45 20  7 26 45 45 50 17 41 59 50]
L^(-1) * S^2 * L = 
[34 12 70 21 36  2  2 43  7 14  2]
[ 1 54 59 12 64 35  9  7 49 11 49]
[69 14 10 19 16 27 11  9 26 10 45]
[70 17 41 13 35 58 19 29 70  5 30]
[68 69 67 37 63 69 15 64 66 28 26]
[18 29 64 38 63 67 15 27 64  6 26]
[ 0 12 40 41 48 30 46 52 39 48 58]
[22  3 28 35 55 30 15 17 22 49 55]
[50 55 55 61 45 23 24 32 10 59 69]
[27 21 68 56 67 49 64 53 42 46 14]
[42 66 16 29 42 42 23 49 43  3 23]
R^(-1) * S^8 = 
[51  9 22 61 63 14  2  4 18 18 23]
[33 53 31 31 62 21 66  7 66 68  7]
[59 19 32 21 13 34 16 43 49 25  7]
[44 37  4 29 70 50 46 39 55  4 65]
[29 63 29 43 47 28 40 33  0 62  8]
[45 62 36 68 10 66 26 48 10  6 61]
[43 30 25 18 23 38 61  0 52 46 35]
[ 3 40  6 45 20 55 35 67 25 14 63]
[15 30 61 66 25 33 14 20 60 50 50]
[29 15 53 22 55 64 69 56 44 40  8]
[28 40 69 60 28 41  9 14 29  4 29]

```  
  
看看怎么处理flag的先  
```
def cross(m):
    return alphabet.index(m)

def prepare(msg):
    A = zero_matrix(GF(p), 11, 11)
    for k in range(len(msg)):
        i, j = 5*k // 11, 5*k % 11
        A[i, j] = cross(msg[k])
    return A

A = prepare(flag)

```  
  
建了个   
 的零矩阵，然后将 flag 的每一个字符转化为在字符集里的索引放了进去，两两间隔4个元素，类似这样  
```
[11  0  0  0  0 11  0  0  0  0 11]
[ 0  0  0  0 11  0  0  0  0 11  0]
[ 0  0  0 11  0  0  0  0 11  0  0]
[ 0  0 11  0  0  0  0 11  0  0  0]
[ 0 11  0  0  0  0 11  0  0  0  0]
[11  0  0  0  0 11  0  0  0  0 11]
[ 0  0  0  0 11  0  0  0  0 11  0]
[ 0  0  0 11  0  0  0  0 11  0  0]
[ 0  0 11  0  0  0  0 11  0  0  0]
[ 0 11  0  0  0  0 11  0  0  0  0]
[11  0  0  0  0 11  0  0  0  0  0]

```  
  
然后生成了一个密钥  
```
def keygen():
    R = random_matrix(GF(p), 11, 11)
    while True:
        S = random_matrix(GF(p), 11, 11)
        if S.rank() == 11:
            _, L, U = S.LU()
            return R, L, U
            
key = keygen()

```  
  
R 和 S 是一个随机矩阵，  
  
L，U 分别是 S的下三角矩阵和上三角矩阵，会有  
  
然后就是加密  
```
def encrypt(A, key):
    R, L, U = key
    S = L * U
    X = A + R
    Y = S * X
    E = L.inverse() * Y
    return E

```  
  
  
  
  
然后题目提供了  
  
想法就是怎么用题目提供的这几个东西把   
 里的   
 提出来叭  
  
首先的一个想法是把   
 搞出来，因为   
 里面有   
，  
  
因为我们有   
，所以我们搞到   
 就行  
  
  
因为我们有   
 ，所以我们搞到   
 就行  
  
注意到  
  
所以我们也能搞到  
  
然后我们就能从   
 中提出   
 来，从而获取flag了。  
  
脚本来自https://blog.cryptohack.org/cryptoctf2021-medium#onlude  
```
E = Matrix(GF(71),[[25,55,61,28,11,46,19,50,37,5,21],
[20,57,39,9,25,37,63,31,70,15,47],
[56,31,1,1,50,67,38,14,42,46,14],
[42,54,38,22,19,55,7,18,45,53,39],
[55,26,42,15,48,6,24,4,17,60,64],
[1,38,50,10,19,57,26,48,6,4,14],
[13,4,38,54,23,34,54,42,15,56,29],
[26,66,8,48,6,70,44,8,67,68,65],
[56,67,49,61,18,34,53,21,7,48,32],
[15,70,10,34,1,57,70,27,12,33,46],
[25,29,20,21,30,55,63,49,11,36,7]])

hint1 = Matrix(GF(71),[[50,8,21,16,13,33,2,12,35,20,14],
[36,55,36,34,27,28,23,21,62,17,8],
[56,26,49,39,43,30,35,46,0,58,43],
[11,25,25,35,29,0,22,38,53,51,58],
[34,14,69,68,5,32,27,4,27,62,15],
[46,49,36,42,26,12,28,60,54,66,23],
[69,55,30,65,56,13,14,36,26,46,48],
[25,48,16,20,34,57,64,62,61,25,62],
[68,39,11,40,25,11,7,40,24,43,65],
[54,20,40,59,52,60,37,14,32,44,4],
[45,20,7,26,45,45,50,17,41,59,50]])

hint2=Matrix(GF(71),[[34,12,70,21,36,2,2,43,7,14,2],
[1,54,59,12,64,35,9,7,49,11,49],
[69,14,10,19,16,27,11,9,26,10,45],
[70,17,41,13,35,58,19,29,70,5,30],
[68,69,67,37,63,69,15,64,66,28,26],
[18,29,64,38,63,67,15,27,64,6,26],
[0,12,40,41,48,30,46,52,39,48,58],
[22,3,28,35,55,30,15,17,22,49,55],
[50,55,55,61,45,23,24,32,10,59,69],
[27,21,68,56,67,49,64,53,42,46,14],
[42,66,16,29,42,42,23,49,43,3,23]])

hint3=Matrix(GF(71),[[51,9,22,61,63,14,2,4,18,18,23],
[33,53,31,31,62,21,66,7,66,68,7],
[59,19,32,21,13,34,16,43,49,25,7],
[44,37,4,29,70,50,46,39,55,4,65],
[29,63,29,43,47,28,40,33,0,62,8],
[45,62,36,68,10,66,26,48,10,6,61],
[43,30,25,18,23,38,61,0,52,46,35],
[3,40,6,45,20,55,35,67,25,14,63],
[15,30,61,66,25,33,14,20,60,50,50],
[29,15,53,22,55,64,69,56,44,40,8],
[28,40,69,60,28,41,9,14,29,4,29]])

U = hint2/hint1
R = (hint3/((hint1*U)^4)).inverse()
A = U.inverse()*E-R
alphabet = '=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$!?_{}<>'
flag = ''
for k in range(24):
    i, j = 5*k // 11, 5*k % 11
    flag+=alphabet[A[i, j]]
print('CCTF{'+flag+'}')

```  
- ## Maid  
  
POINTS：119  
  
考点：Rabin Cryptosystem  
```
#!/usr/bin/python3

from Crypto.Util.number import *
from gmpy2 import *
from secret import *
from flag import flag

global nbit
nbit = 1024

def keygen(nbit):
    while True:
        p, q = [getStrongPrime(nbit) for _ in '01']
        if p % 4 == q % 4 == 3:
            return (p**2)*q, p

def encrypt(m, pubkey):
    if GCD(m, pubkey) != 1 or m >= 2**(2*nbit - 2):
        return None
    return pow(m, 2, pubkey)

def flag_encrypt(flag, p, q):
    m = bytes_to_long(flag)
    assert m < p * q
    return pow(m, 65537, p * q)

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

def main():
    border = "+"
    pr(border*72)
    pr(border, "  hi all, welcome to Rooney Oracle, you can encrypt and decrypt any ", border)
    pr(border, "  message in this oracle, but the flag is still encrypted, Rooney   ", border)
    pr(border, "  asked me to find the encrypted flag, I'm trying now, please help! ", border)
    pr(border*72)

    pubkey, privkey = keygen(nbit)
    p, q = privkey, pubkey // (privkey ** 2)

    while True:
        pr("| Options: \n|\t[E]ncrypt message \n|\t[D]ecrypt ciphertext \n|\t[S]how encrypted flag \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 'e':
            pr("| Send the message to encrypt: ")
            msg = sc()
            try:
                msg = int(msg)
            except:
                die("| your message is not integer!!")
            pr(f"| encrypt(msg, pubkey) = {encrypt(msg, pubkey)} ")
        elif ans == 'd':
            pr("| Send the ciphertext to decrypt: ")
            enc = sc()
            try:
                enc = int(enc)
            except:
                die("| your message is not integer!!")
            pr(f"| decrypt(enc, privkey) = {decrypt(enc, privkey)} ")
        elif ans == 's':
            pr(f'| enc = {flag_encrypt(flag, p, q)}')
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()

```  
  
这里用的是 Rabin 密码系统，但是  
  
然后题目提供三个功能，  
  
e:使用公钥加密  
  
d:使用私钥解密 **未知**  
  
s:给出flag的密文  
  
 也没给，不过这好搞，用两次加密功能，然后   
 就好了。  
  
问题出在源码没有给出这个rabin密码系统的解密代码，那么只能fuzz一下，看有没有机会分解出   
 来。  
  
一般都是会传一下特殊的值，比如1，0，-1这样去fuzz，但是由于本地没法搭环境，就没法自己搞测试样例了，还挺麻烦的。  
  
（这里后面放出源码了，就模拟一下当时的场景好了。）  
```
def decrypt(c, privkey):
    m_p = pow(c, (privkey + 1) // 4, privkey)
    i = (c - pow(m_p, 2)) // privkey
    j = i * inverse(2*m_p, privkey) % privkey
    m = m_p + j * privkey
    if 2*m < privkey**2:
        return m
    else:
        return privkey**2 - m

```  
  
这里本地测试的时候，会发现有时候，解密的值再加密，并不能变回去，感觉就挺奇怪的。  
  
然后测试会发现  
  
那么就能分解n了，然后就是常规解密 RSA 的操作了。  
  
脚本来自 https://blog.cryptohack.org/cryptoctf2021-medium#maid  
```
from pwn import *
from Crypto.Util.number import *
from math import gcd
import random

r = remote('04.cr.yp.toc.tf', 38010)

def encrypt(msg):
    r.recvuntil(b"[Q]uit")
    r.sendline(b"E")
    r.recvuntil(b"encrypt: ")
    r.sendline(str(msg))
    r.recvuntil(b" = ")
    return int(r.recvline().strip())

def decrypt(msg):
    r.recvuntil(b"[Q]uit")
    r.sendline(b"D")
    r.recvuntil(b"decrypt: ")
    r.sendline(str(msg))
    r.recvuntil(b" = ")
    return int(r.recvline().strip())

def get_flag():
    r.recvuntil(b"[Q]uit")
    r.sendline(b"S")
    r.recvuntil(b" = ")
    return int(r.recvline().strip())

def recover_n():
    # Obtain kn
    m = 2**1536 - random.randint(1,2**1000)
    c = encrypt(m)
    n = m**2 - c
    # Remove all factors of two
    while n%2 == 0:
        n = n // 2
    # Compute a few more GCD to remove any other factors.
    for _ in range(10):
        m = 2**1536 - random.randint(1,2**1000)
        c = encrypt(m)
        n = gcd(n, m**2 - c)
    return n

def dec_flag(p,q):
    c = get_flag()
    d = pow(0x10001, -1, (p-1)*(q-1))
    m = pow(c,d,p*q)
    return long_to_bytes(m)

def recover_factors(n):
    X = decrypt(-1)
    p = gcd(X - 1, n)
    assert isPrime(p)
    q = n // (p*p) 
    assert isPrime(q)
    return p, q

n = recover_n()
p, q = recover_factors(n)
flag = dec_flag(p,q)
print(flag)
# CCTF{___Ra8!N_H_Cryp70_5YsT3M___}

```  
  
这里我们回头看一下解密函数  
  
  
  
  
  
如果  
  
如果  
  
最初加密的时候似乎也限制了  
  
推导一下，如果传过去正常的明文   
，我们得到密文  
  
（不难知道   
，  
，  
 ）  
  
  
  
  
 			这一步似乎是想得到   
 ？  
  
如果传   
 去解密就会有  
  
  
如果   
：  
  
  
  
  
那么  
  
如果   
：  
  
  
  
	(然而好像触发   
，所以得到   
)  
  
那么  
  
比赛的时候没有给出解密函数，，emmm，就会觉得有一点点脑洞。  
- ## Wolf  
  
PONITS：128  
  
考点：爆破  
```
#!/usr/bin/env python3

from Cryptodome.Cipher import AES
import os, time, sys, random
from flag import flag

passphrase = b'HungryTimberWolf'

def encrypt(msg, passphrase, niv):
    msg_header = 'EPOCH:' + str(int(time.time()))
    msg = msg_header + "\n" + msg + '=' * (15 - len(msg) % 16)
    aes = AES.new(passphrase, AES.MODE_GCM, nonce = niv)
    enc = aes.encrypt_and_digest(msg.encode('utf-8'))[0]
    return enc

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

def main():
    border = "+"
    pr(border*72)
    pr(border, "  hi wolf hunters, welcome to the most dangerous hunting ground!!   ", border)
    pr(border, "  decrypt the encrypted message and get the flag as a nice prize!   ", border)
    pr(border*72)

    niv = os.urandom(random.randint(1, 11))
    flag_enc = encrypt(flag, passphrase, niv)

    while True:
        pr("| Options: \n|\t[G]et the encrypted flag \n|\t[T]est the encryption \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 'g':
            pr(f'| encrypt(flag) = {flag_enc.hex()}')
        elif ans == 't':
            pr("| Please send your message to encrypt: ")
            msg_inp = sc()
            enc = encrypt(msg_inp, passphrase, niv).hex()
            pr(f'| enc = {enc}')
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()

```  
  
看到题目的附件，好像把AES-GCM加密用的key都给出来了  
```
passphrase = b'HungryTimberWolf'

```  
  
然后iv没给，长度也不确定，但是在1 和 11之间  
```
niv = os.urandom(random.randint(1, 11))

```  
  
emmm，那就暴力连接，当niv=1的时候，再爆破一下niv的值进行解密，一共也就256种可能。  
  
期望概率大概也就是  
```
from pwn import *
from Crypto.Cipher import AES
import os, time, sys, random

def dec(line):
    for iv in range(256):
        a = AES.new(b'HungryTimberWolf', AES.MODE_GCM, nonce=bytes([iv]))
        flag = a.decrypt(binascii.unhexlify(line))
        if b'CTF' in flag:
            print(flag)
            exit()
            
while True:
    sh = remote('01.cr.yp.toc.tf', 27010)
    sh.recvuntil("[Q]uit\n")
    sh.sendline('g')
    sh.recvuntil("| encrypt(flag) = ")
    enc_flag = sh.recvuntil("\n")[:-1]
    dec(enc_flag)
    sh.close()


```  
- ## Ferman  
  
POINTS:134  
  
考点：高斯整数  
```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+  hi talented participants, welcome to the FERMAN cryptography task!  +
+  Solve the given equations and decrypt the encrypted flag! Enjoy!    +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

| Parameters generation is a bit time consuming, so please be patient :P
| Options: 
|   [P]rint encrypted flag 
|   [R]eveal the parameters 
|   [Q]uit

P
| encrypt(flag) = 6489656589950752810044571176882070993656025408411955877914111875896024399252967804237101085443293019406006339555779534657926807551928549712558667515175079267695028070934727514846970003337126120540450206565849474378607706030211234939933160392491902242074123763448231072583065175864490510115483208842110529309232348180718641618424365058379284549574700049803925884878710773408472100779358561980206902500388524570616750475958017638946408491011264747032498524679282489181606124604218147

R
    e = 65537
    isPrime(p) = True
    isPrime(q) = True
    n = p * q
    (p - 127)**2 + (q - 184)**2 = 13809252727788824044233595548226590341967726502046327883413398709726819135921363848617960542444505497356040393690402758557636039683075007984614264314802550433942617885990971202110511768121760826488944622697964930982921462840320850014092598270493079542993367042001339267321218767132063176291998391714014192946596879176425904447127657664796094937171819714510504836456988487840790317576922986001688147359646287894578550322731904860694734616037751755921771706899493873123836562784063321
    m = bytes_to_long(flag)
    c = pow(m, e, n) 

```  
  
经典给出   
 相关额外信息进行对   
 的分解。  
  
给出  
  
这里经过测试发现   
 是一个七次幂，即  
```
sage: w=13809252727788824044233595548226590341967726502046327883413398709726819135921363848617960542444505497356040393690402758557636039683075007984614264314802550433942617885990971202110511768121760826488944622697964930982921462840320850014092598270493079542993367042001339267321218767132063176291998391714014192946596879176425904447127657664796094937171819714510504836456988487840790317576922986001688147359646287894578550322731904860694734616037751755921771706899493873123836562784063321
sage: w^(1/7)
542387941227387369715206573048698209530476609597527643690717423409961


```  
  
设  
  
那么我们有  
  
由于   
，  
  
若我们能将   
 分解成共轭的两部分  
，那么就会有  
```
sage: C = ZZ[i]
sage: factor(C(z))
(-15642728159752*I - 39850152715295) * (13420641811410*I - 19188039291907) * (19188039291907*I - 13420641811410) * (-4190*I - 9649) * (4190*I - 9649) * (-18*I - 17) * (-3*I - 8) * (3*I - 8) * (-3*I + 10) * (3*I + 10) * (17*I + 18) * (-15642728159752*I + 39850152715295)

```  
  
很对称，但是emmm，排列组合太多了，，我们可以换一组数据  
```
a = 2265 
b = 902 
w = 24007015341450638047707811509679207068051724063799752621201994109462561550079479155110637624506028551099549192036601169213196430196182069103932872524092047760624845002308713558682251660517182097667675473038586407097498167776645896369165963981698265040400341878755056463554861788991872633206414266159558715922583613630387512303492920597052611976890648632123534922756985895479931541478630417251021677032459939450624439421018438357005854556082128718286537575550378203702362524442461229
flag_enc = 10564879569008106132040759805988959471544940722100428235462653367215001622634768902220485764070394703676633460036566842009467954832811287152142597331508344786167188766356935684044757086902094847810694941751879500776345600036096556068243767090470376672110936445246103465175956767665996275085293250901512809704594905257754009538501795362031873203086994610168776981264025121998840163864902563628991590207637487738286741829585819040077197755226202284847

```  
```
a = 2265 
b = 902 
z = w^(1/7)
C = ZZ[i]
factor(C(z))

(-I) * (-1236649975237776943493190425869173*I - 3575914522629734831030006136433790) * (-5*I - 4) * (4*I + 5) * (-1236649975237776943493190425869173*I + 3575914522629734831030006136433790)

```  
  
测试  
```
w = 24007015341450638047707811509679207068051724063799752621201994109462561550079479155110637624506028551099549192036601169213196430196182069103932872524092047760624845002308713558682251660517182097667675473038586407097498167776645896369165963981698265040400341878755056463554861788991872633206414266159558715922583613630387512303492920597052611976890648632123534922756985895479931541478630417251021677032459939450624439421018438357005854556082128718286537575550378203702362524442461229
zx = (-1236649975237776943493190425869173*I + 3575914522629734831030006136433790) * (-5*I - 4)
x = abs((zx^7).imag())
y = abs((zx^7).real())
print(x)
print(y)
assert x^2+y^2 == w
is_prime(x+2265)
is_prime(x+902)


```  
  
返回  
```
3515251100858858796435724523870761115321577101490666287216209907489403476079222276536571942496157069855565014771125798502774268554017196492328530962886884456876064742139864478104832820555776577341055529681241338289453827370647829795170811402
3413213301181339793171422358348736699126965473930685311400429872075816456893055375667482794611435574843396575239764759040242158681190020317082329009191911152126267671754529169503180596722173728126136891139303943035843711591741985591269095075
True
False

```  
  
于是我们得到素数  
```
x+2265=3515251100858858796435724523870761115321577101490666287216209907489403476079222276536571942496157069855565014771125798502774268554017196492328530962886884456876064742139864478104832820555776577341055529681241338289453827370647829795170813667

```  
```
from Crypto.Util.number import *

p = 3515251100858858796435724523870761115321577101490666287216209907489403476079222276536571942496157069855565014771125798502774268554017196492328530962886884456876064742139864478104832820555776577341055529681241338289453827370647829795170813667  
q = 3413213301181339793171422358348736699126965473930685311400429872075816456893055375667482794611435574843396575239764759040242158681190020317082329009191911152126267671754529169503180596722173728126136891139303943035843711591741985591269095977
phi = (p-1)*(q-1)
d = pow(0x10001, -1, phi)
print(long_to_bytes(pow(flag_enc,d,p*q)))
b'CCTF{Congrats_Y0u_5OLv3d_x**2+y**2=z**7}'

```  
  
（PS：对于方程  
，我们利用高斯分解似乎能够找到很多组满足条件的解   
，取决于高斯分解   
 后它能有多少个因子）  
- ## RSAphantine  
  
POINTS:142  
  
考点：丢番图方程  
```
2*z**5 - x**3 + y*z = 47769864706750161581152919266942014884728504309791272300873440765010405681123224050402253883248571746202060439521835359010439155922618613520747411963822349374260144229698759495359592287331083229572369186844312169397998958687629858407857496154424105344376591742814310010312178029414792153520127354594349356721
x**4 + y**5 + x*y*z = 89701863794494741579279495149280970802005356650985500935516314994149482802770873012891936617235883383779949043375656934782512958529863426837860653654512392603575042842591799236152988759047643602681210429449595866940656449163014827637584123867198437888098961323599436457342203222948370386342070941174587735051
y**6 + 2*z**5 + z*y = 47769864706750161581152919266942014884728504309791272300873440765010405681123224050402253883248571746202060439521835359010439155922618613609786612391835856376321085593999733543104760294208916442207908167085574197779179315081994735796390000652436258333943257231020011932605906567086908226693333446521506911058
p = nextPrime(x**2 + z**2 + y**2 << 76)
q = nextPrime(z**2 + y**3 - y*x*z ^ 67)
n, e = p * q, 31337
m = bytes_to_long(FLAG)
c = pow(m, e, n)
c = 486675922771716096231737399040548486325658137529857293201278143425470143429646265649376948017991651364539656238516890519597468182912015548139675971112490154510727743335620826075143903361868438931223801236515950567326769413127995861265368340866053590373839051019268657129382281794222269715218496547178894867320406378387056032984394810093686367691759705672

```  
  
题目的target很明显了，显然解关于x,y,z的方程组了。  
1.   
1.   
1.   
很直观的会想要用3式减去 1式  
  
  
用sage处理一下  
```
sage: f=y^6+x^3
sage: factor(f)
(y^4 - x*y^2 + x^2)*(y^2 + x)
sage: factor(c-a)
3133713317731333 * 28413320364759425177418147555143516002041291710972733253944530195017276664069717887927099709630886727522090965378073004342203980057853092114878433424202989


```  
  
（感觉出题人处理的比较好，c-a只有两个因子）那么显然，这里有  
  
有了这一条我们再代入   
 就可以解出   
 了  
  
有了   
 代入 2 式就能解出   
 了。  
  
从而进行RSA参数的生成，解密获得flag。  
  
脚本来自https://jsur.in/posts/2021-08-01-crypto-ctf-2021-writeups  
```
from Crypto.Util.number import long_to_bytes

c1 = 47769864706750161581152919266942014884728504309791272300873440765010405681123224050402253883248571746202060439521835359010439155922618613520747411963822349374260144229698759495359592287331083229572369186844312169397998958687629858407857496154424105344376591742814310010312178029414792153520127354594349356721
c2 = 89701863794494741579279495149280970802005356650985500935516314994149482802770873012891936617235883383779949043375656934782512958529863426837860653654512392603575042842591799236152988759047643602681210429449595866940656449163014827637584123867198437888098961323599436457342203222948370386342070941174587735051
c3 = 47769864706750161581152919266942014884728504309791272300873440765010405681123224050402253883248571746202060439521835359010439155922618613609786612391835856376321085593999733543104760294208916442207908167085574197779179315081994735796390000652436258333943257231020011932605906567086908226693333446521506911058

R.<x,y,z> = PolynomialRing(QQ)
delta = 3133713317731333
f1 = y^6 + (delta - y^2)^3 - (c3 - c1)
y = f1.univariate_polynomial().roots()[0][0]
x = delta - y^2
f2 = x^4 + y^5 + x*y*z - c2
z = f2.univariate_polynomial().roots()[0][0]

x = int(x)
y = int(y)
z = int(z)

p = Integer(x**2 + z**2 + y**2 << 76).next_prime()
q = Integer(z**2 + y**3 - y*x*z ^^ 67).next_prime()
n, e = p * q, 31337
c = 486675922771716096231737399040548486325658137529857293201278143425470143429646265649376948017991651364539656238516890519597468182912015548139675971112490154510727743335620826075143903361868438931223801236515950567326769413127995861265368340866053590373839051019268657129382281794222269715218496547178894867320406378387056032984394810093686367691759705672
d = pow(e, -1, (p-1)*(q-1))
m = pow(c, int(d), n)
print(long_to_bytes(m).decode())
CCTF{y0Ur_jO8_C4l13D_Diophantine_An4LySI5!}

```  
- ## FROZEN  
  
POINTS: 142  
  
考点：已知明文攻击（非预期？）  
```
from Crypto.Util.number import *
from gmpy2 import *
import sys, random, string

flag = 'fakeflag{}'

def genrandstr(N):
    return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(N))

def paramaker(nbit):
    p = getPrime(nbit)
    r = getRandomRange(1, p)
    return p, r

def keygen(params, l, d):
    p, r = params
    s = getRandomRange(1, p)
    U = [pow(r, c + 1, p) * s % p for c in range(0,l)]
    V = [int(bin(u)[2:][:-d] + '0' * d, 2) for u in U]
    S = [int(bin(u)[2:][-d:], 2) for u in U]
    privkey, pubkey = S, V
    return pubkey, privkey

def sign(msg, privkey, d):
    msg = msg.encode('utf-8')
    l = len(msg) // 4
    M = [bytes_to_long(msg[4*i:4*(i+1)]) for i in range(l)]
    q = int(next_prime(max(M)))
    sign = [M[i]*privkey[i] % q for i in range(l)]
    return sign

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

def main():
    border = "+"
    pr(border*72)
    pr(border, " hi young cryptographers, welcome to the frozen signature battle!!  ", border)
    pr(border, " Your mission is to forge the signature for a given message, ready?!", border)
    pr(border*72)

    randstr = genrandstr(20)
    nbit, dbit = 128, 32
    params = paramaker(nbit)
    l = 5
    pubkey, privkey = keygen(params, l, dbit)

    while True:
        pr("| Options: \n|\t[S]how the params \n|\t[P]rint pubkey \n|\t[E]xample signature \n|\t[F]orge the signature \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 's':
            pr(f'| p = {params[0]}')
            pr(f'| r = {params[1]}')
        elif ans == 'p':
            pr(f'pubkey = {pubkey}')
        elif ans == 'e':
            pr(f'| the signature for "{randstr}" is :')
            pr(f'| signature = {sign(randstr, privkey, dbit)}')
        elif ans == 'f':
            randmsg = genrandstr(20)
            pr(f'| send the signature of the following message like example: {randmsg}')
            SIGN = sc()
            try:
                SIGN = [int(s) for s in SIGN.split(',')]
            except:
                die('| your signature is not valid! Bye!!')
            if SIGN == sign(randmsg, privkey, dbit):
                die(f'| Congrats, you got the flag: {FLAG}')
            else:
                die(f'| Your signature is not correct, try later! Bye!')
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()

```  
  
题目是一个签名服务，使用私钥对4个字节的明文进行签名  
  
 是一个约为 30bit 的素数  
  
私钥的生成来源于   
 的低 32 位。  
  
但是题目给出了一个消息的签名示例，利用其   
，我们可以恢复  
  
但是由于   
 只有30比特左右，所以我们还需要做一点点小小的爆破，而判断依据则是  
  
exp  
```
from Crypto.Util.number import *
from gmpy2 import *

# 交互获取签名样例计算大部分私钥: e
msg = "gxOy9KYScvLF2tWUpkg0".encode('utf-8')


l = len(msg) // 4
M = [bytes_to_long(msg[4*i:4*(i+1)]) for i in range(l)]
q = int(next_prime(max(M)))
sign = [289279587, 50849811, 1632438391, 537783778, 611375482]
privkey = [inverse(M[i],q)*sign[i] % q for i in range(l)]

# 交互获取公钥: p
pubkey = [43888590349289262389019236090217758720, 17879334018861290280325290839018307584, 40499489748639202207722187467891146752, 178025246158865738197422650069448916992, 96934554205183278449061380907857870848]

key=[]
for i in range(5):
 key.append(pubkey[i]+privkey[i])
 
# 交互获取参数: s
p = 178511102601149595520550176105220942341
r = 125432576416753760620313745406675102980

# 爆破剩余私钥
for i in range(0,4):
 for j in range(0,4):
  if (key[1]+j*q) * inverse(key[0]+i*q,p)%p == r:
   key[0] += i*q
   key[1] += j*q
   print(i,j)
   break

for i in range(2,5):
 for k in range(0,4):
  if (key[i]+k*q) * inverse(key[i-1],p)%p == r:
   key[i] += k*q
   print(i,k)
   break
privkey = [each % (2**32) for each in key]

def sign(msg, privkey):
    msg = msg.encode('utf-8')
    l = len(msg) // 4
    M = [bytes_to_long(msg[4*i:4*(i+1)]) for i in range(l)]
    q = int(next_prime(max(M)))
    sign = [M[i]*privkey[i] % q for i in range(l)]
    return sign
    
# 交互伪造签名: f
print(sign("4bV9K70jeYOoogSnGsTc", privkey))


```  
  
PS：这道题的flag是 CCTF{Lattice_bA5eD_T3cHn1QuE_70_Br34K_LCG!!}，看来作者原意应该是让我们有lattice去恢复未知位，不过这里通过已知明文攻击能够获取到的低位太多了，这里需要再稍微调整一下。  
- ## LINDA  
  
POINTS：169  
  
考点：离散对数，  
 光滑  
```
#!/usr/bin/env python3

from Crypto.Util.number import *
from math import gcd
from flag import flag

def keygen(p):
    while True:
        u = getRandomRange(1, p)
        if pow(u, (p-1) // 2, p) != 1:
            break
    x = getRandomRange(1, p)
    w = pow(u, x, p)
    while True:
        r = getRandomRange(1, p-1)
        if gcd(r, p-1) == 1:
            y = x * inverse(r, p-1) % (p-1)
            v = pow(u, r, p)
            return u, v, w
    
def encrypt(m, pubkey):
    p, u, v, w = pubkey
    assert m < p
    r, s = [getRandomRange(1, p) for _ in '01']
    ca = pow(u, r, p)
    cb = pow(v, s, p)
    cc = m * pow(w, r + s, p) % p
    enc = (ca, cb, cc)
    return enc

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

def main():
    border = "+"
    pr(border*72)
    pr(border, "  .:::::: LINDA Cryptosystem has high grade security level ::::::.  ", border)
    pr(border, "  Can you break this cryptosystem and find the flag?                ", border)
    pr(border*72)

    pr('| please wait, preparing the LINDA is time consuming...')
    from secret import p
    u, v, w = keygen(p)
    msg = bytes_to_long(flag)
    pubkey = p, u, v, w
    enc = encrypt(msg, pubkey)
    while True:
        pr("| Options: \n|\t[E]xpose the parameters \n|\t[T]est the encryption \n|\t[S]how the encrypted flag \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 'e':
            pr(f'| p = {p}')
            pr(f'| u = {u}')
            pr(f'| v = {v}')
            pr(f'| w = {w}')
        elif ans == 's':
            print(f'enc = {enc}')
        elif ans == 't':
            pr('| send your message to encrypt: ')
            m = sc()
            m = bytes_to_long(m.encode('utf-8'))
            pr(f'| encrypt(m) = {encrypt(m, pubkey)}')
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()

```  
  
这道题目有一个 from secret import p，交互获取样例会发现   
 是光滑的  
```
p = 31236959722193405152010489304408176327538432524312583937104819646529142201202386217645408893898924349364771709996106640982219903602836751314429782819699
p - 1 = 2 * 3 * 11 * 41 * 137 * 223 * 7529 * 14827 * 15121 * 40559 * 62011 * 429083 * 916169 * 3810461 * 4316867 * 20962993 * 31469027 * 81724477 * 132735437 * 268901797 * 449598857 * 2101394579 * 2379719473 * 5859408629 * 11862763021 * 45767566217

```  
  
然后   
 已知，再由  
  
  
我们对   
 解离散对数就能获取   
，然后就能计算   
，从而解密获取  
  
exp  
```
# sage

# 交互获取 cc,cb,ca,p,u,v,w

r = discrete_log(Mod(ca, p), Mod(u, p)) 
s = discrete_log(Mod(cb, p), Mod(v, p))
m = cc * pow(w, -(r + s), p) % p
print(long_to_bytes(m))

```  
  
PS：这道题能有这么高的分倒是有点不可思议，可能大部分选手没发现   
 是光滑的叭。  
  
       
