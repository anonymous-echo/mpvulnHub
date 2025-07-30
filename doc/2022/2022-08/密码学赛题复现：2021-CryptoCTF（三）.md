#  ​密码学赛题复现：2021-CryptoCTF（三）   
原创 核心基础实验室  山石网科安全技术研究院   2022-08-12 10:43  
  
```
Crypto CTF is an online competition for hackers to test, evaluate, and expand their cryptography exploiting skills. In this CTF, we will provide various crypto challenges regarding modern cryptography techniques.
All crypto lovers are most welcome!
Crypto CTF is a revenge for everlasting complaints by CTF participants about crypto challenges in CTF contests. In this brand-new tournament, we are trying to provide the crypto lovers with fun and challenging pure crypto tasks to squeeze their heart and test their passion for cryptography.
Each task will be based on a particular cryptographic primitive, or it will include a direct application of cryptography in other fields.
The organizers of these tournaments generously offer their skills' knowledge to design original Crypto tasks and challenges for similar contests.Long Live Crypto :)
```  
  
最后一part…  
- ## TinyECC  
  
POINTS：217  
  
考点：椭圆曲线离散对数  
```
#!/usr/bin/env python3

from mini_ecdsa import *
from Crypto.Util.number import *
from flag import flag

def tonelli_shanks(n, p):
    if pow(n, int((p-1)//2), p) == 1:
            s = 1
            q = int((p-1)//2)
            while True:
                if q % 2 == 0:
                    q = q // 2
                    s += 1
                else:
                    break
            if s == 1:
                r1 = pow(n, int((p+1)//4), p)
                r2 = p - r1
                return r1, r2
            else:
                z = 2
                while True:
                    if pow(z, int((p-1)//2), p) == p - 1:
                        c = pow(z, q, p)
                        break
                    else:
                        z += 1
                r = pow(n, int((q+1)//2), p)
                t = pow(n, q, p)
                m = s
                while True:
                    if t == 1:
                        r1 = r
                        r2 = p - r1
                        return r1, r2
                    else:
                        i = 1
                        while True:
                            if pow(t, 2**i, p) == 1:
                                break
                            else:
                                i += 1
                        b = pow(c, 2**(m-i-1), p)
                        r = r * b % p
                        t = t * b ** 2 % p
                        c = b ** 2 % p
                        m = i
    else:
        return False

def random_point(p, a, b):
    while True:
        gx = getRandomRange(1, p-1)
        n = (gx**3 + a*gx + b) % p
        gy = tonelli_shanks(n, p)
        if gy == False:
            continue
        else:
            return (gx, gy[0])

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
    pr(border, "  Dual ECC means two elliptic curve with same coefficients over the ", border)
    pr(border, "  different fields or ring! You should calculate the discrete log   ", border)
    pr(border, "  in dual ECCs. So be smart in choosing the first parameters! Enjoy!", border)
    pr(border*72)

    bool_coef, bool_prime, nbit = False, False, 128
    while True:
        pr(f"| Options: \n|\t[C]hoose the {nbit}-bit prime p \n|\t[A]ssign the coefficients \n|\t[S]olve DLP \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 'a':
            pr('| send the coefficients a and b separated by comma: ')
            COEFS = sc()
            try:
                a, b = [int(_) for _ in COEFS.split(',')]
            except:
                die('| your coefficients are not valid, Bye!!')
            if a*b == 0:
                die('| Kidding me?!! a*b should not be zero!!')
            else:
                bool_coef = True
        elif ans == 'c':
            pr('| send your prime: ')
            p = sc()
            try:
                p = int(p)
            except:
                die('| your input is not valid :(')
            if isPrime(p) and p.bit_length() == nbit and isPrime(2*p + 1):
                q = 2*p + 1
                bool_prime = True
            else:
                die(f'| your integer p is not {nbit}-bit prime or 2p + 1 is not prime, bye!!')
        elif ans == 's':
            if bool_coef == False:
                pr('| please assign the coefficients.')
            if bool_prime == False:
                pr('| please choose your prime first.')
            if bool_prime and bool_coef:
                Ep = CurveOverFp(0, a, b, p)
                Eq = CurveOverFp(0, a, b, q)

                xp, yp = random_point(p, a, b)
                P = Point(xp, yp)

                xq, yq = random_point(q, a, b)
                Q = Point(xq, yq)

                k = getRandomRange(1, p >> 1)
                kP = Ep.mult(P, k)

                l = getRandomRange(1, q >> 1)
                lQ = Eq.mult(Q, l)
                pr('| We know that: ')
                pr(f'| P = {P}')
                pr(f'| k*P = {kP}')
                pr(f'| Q = {Q}')
                pr(f'| l*Q = {lQ}')
                pr('| send the k and l separated by comma: ')
                PRIVS = sc()
                try:
                    priv, qriv = [int(s) for s in PRIVS.split(',')]
                except:
                    die('| your input is not valid, Bye!!')
                if priv == k and qriv == l:
                    die(f'| Congrats, you got the flag: {flag}')
                else:
                    die('| sorry, your keys are not correct! Bye!!!')
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()

```  
  
题目的意思是让你输入系数   
 来构造一条曲线，然后解一个椭圆曲线上的离散对数问题。  
  
这里有两个思路，一个是构造   
，使用smart attack，或者   
 可以使用weil pair 去做。  
  
这里是用smart attack的方法，先根据http://www.monnerat.info/publications/anomalous.pdf生成奇异曲线的参数  
```
# http://www.monnerat.info/publications/anomalous.pdf
D = 19
j = -2^15*3^3

def anon_prime(m):
    while True:
        p = (19*m*(m + 1)) + 5
        if is_prime(p):
            return m, p
        m += 1

curves = []
def anom_curve():
    m = 2**61 + 2**60 # chosen so the curves have bit length 128
    while True:
        m, p = anon_prime(m)
        a = (-3*j * inverse_mod((j - 1728), p)) % p
        b = (2*j * inverse_mod((j - 1728), p)) % p
        E = EllipticCurve(GF(p), [a,b]) 
        if E.order() == p:
            G = E.gens()[0]
            if is_prime(2*p + 1):
                print(f'Found an anomalous prime of bit length: {p.nbits()}')
                print(f'Alse q = 2p+1 is a prime. p={p}')
                if p.nbits() != 128:
                    exit()
                curves.append([p,a,b])
                #print(curves)
        m += 1
anom_curve()   

```  
  
对于第一条曲线我们就可以用smart attack进行离散对数的求解了，  
  
那么第二条曲线，我们就遍历一下，尽量找一条比较光滑的曲线，以便直接使用pohlig-hellman对其继续离散对数求解。  
```
for param in curves:
    p, a, b = param
    q = 2*p + 1
    E1 = EllipticCurve(GF(p), [a,b])
    E2 = EllipticCurve(GF(q), [a,b])
    assert E1.order() == p
    if factor(E2.order())[-1][0] <= 2^32:
        print(factor(E2.order()))
        print(p)

# 2 * 11 * 29 * 269 * 809 * 1153 * 5527 * 1739687 * 272437559 * 1084044811
# 227297987279223760839521045903912023553
# 2^12 * 3^2 * 5^2 * 3943 * 417869 * 2117447 * 204521147 * 691298191
# 227297987279232780301248910046242203569
# 3^3 * 5 * 233 * 241 * 17473333 * 57368039 * 57798431 * 1035039791
# 227297987279245567422831795384518183819


```  
  
一个例子  
```
# E2.order() = 2 * 11 * 29 * 269 * 809 * 1153 * 5527 * 1739687 * 272437559 * 1084044811
p = 227297987279223760839521045903912023553
q = 2*p + 1
a = 120959747616429018926294825597988269841 
b = 146658155534937748221991162171919843659

```  
  
然后进行 smart attack 和 discrete_log  
```
def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

p = 227297987279223760839521045903912023553
q = 2*p + 1
a = 120959747616429018926294825597988269841 
b = 146658155534937748221991162171919843659

Ep = EllipticCurve(GF(p), [a,b])
G = Ep(97161828186858857945099901434400040095,76112161730436240110429589963792144699)
rG = Ep(194119107523766318610516779439078452539,111570625156450061932127850545534033820)

print(SmartAttack(G,rG,p))

Eq = EllipticCurve(GF(q), [a,b])
H = Eq(229869041108862357437180702478501205702,238550780537940464808919616209960416466)
sH = Eq(18599290990046241788386470878953668775,281648589325596060237553465951876240185)

print(H.discrete_log(sH))

```  
  
交互拿到flag：CCTF{ECC_With_Special_Prime5}  
  
不过还有比较简单的方法（也许是非预期），这里只检查了   
 而不是在模   
 下，所以这里可以绕过，从而构造一条奇异曲线   
  
这样就有同态   
，离散对数解起来就很方便了。  
```
p = 227297987279223760839521045903912023553
q = 2*p + 1

Fp = GF(p)
Fq = GF(q)

Px, Py = (171267639996301888897655876215740853691,17515108248008333086755597522577521623)
kPx, kPy = (188895340186764942633236645126076288341,83479740999426843193232746079655679683)
k = Fp(Fp(kPx) / Fp(kPy)) / Fp(Fp(Px) / Fp(Py))

Qx, Qy = (297852081644256946433151544727117912742,290511976119282973548634325709079145116)
lQx, lQy = (83612230453021831094477443040279571268,430089842202788608377537684275601116540)
l = Fq(Fq(lQx) / Fq(lQy)) / Fq(Fq(Qx) / Fq(Qy))

print(f'{k}, {l}')

```  
  
以上脚本来自https://blog.cryptohack.org/cryptoctf2021-hard#tiny-ecc  
- ## ELEGANT CURVE  
  
POINTS：217  
  
考点：椭圆曲线离散对数  
```
from Crypto.Util.number import *
import sys
from flag import flag

def tonelli_shanks(n, p):
    if pow(n, int((p-1)//2), p) == 1:
            s = 1
            q = int((p-1)//2)
            while True:
                if q % 2 == 0:
                    q = q // 2
                    s += 1
                else:
                    break
            if s == 1:
                r1 = pow(n, int((p+1)//4), p)
                r2 = p - r1
                return r1, r2
            else:
                z = 2
                while True:
                    if pow(z, int((p-1)//2), p) == p - 1:
                        c = pow(z, q, p)
                        break
                    else:
                        z += 1
                r = pow(n, int((q+1)//2), p)
                t = pow(n, q, p)
                m = s
                while True:
                    if t == 1:
                        r1 = r
                        r2 = p - r1
                        return r1, r2
                    else:
                        i = 1
                        while True:
                            if pow(t, 2**i, p) == 1:
                                break
                            else:
                                i += 1
                        b = pow(c, 2**(m-i-1), p)
                        r = r * b % p
                        t = t * b ** 2 % p
                        c = b ** 2 % p
                        m = i
    else:
        return False

def add(A, B, p):
    if A == 0:
        return B
    if B == 0:
        return A
    l = ((B[1] - A[1]) * inverse(B[0] - A[0], p)) % p
    x = (l*l - A[0] - B[0]) % p
    y = (l*(A[0] - x) - A[1]) % p
    return (int(x), int(y))

def double(G, a, p):
    if G == 0:
        return G
    l = ((3*G[0]*G[0] + a) * inverse(2*G[1], p)) % p
    x = (l*l - 2*G[0]) % p
    y = (l*(G[0] - x) - G[1]) % p
    return (int(x), int(y))

def multiply(point, exponent, a, p):
    r0 = 0
    r1 = point
    for i in bin(exponent)[2:]:
        if i == '0':
            r1 = add(r0, r1, p)
            r0 = double(r0, a, p)
        else:
            r0 = add(r0, r1, p)
            r1 = double(r1, a, p)
    return r0

def random_point(a, b, p):
    while True:
        x = getRandomRange(1, p-1)
        try:
            y, _ = tonelli_shanks((x**3 + a*x + b) % p, p)
            return (x, y)
        except:
            continue

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
    pr(border, " hi talented cryptographers, the mission is decrypt a secret message", border)
    pr(border, " with given parameters for two elliptic curve, so be genius and send", border)
    pr(border, " suitable parameters, now try to get the flag!                      ", border)
    pr(border*72)

    nbit = 160

    while True:
        pr("| Options: \n|\t[S]end ECC parameters and solve the task \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 's':
            pr("| Send the parameters of first ECC y^2 = x^3 + ax + b like: a, b, p ")
            params = sc()
            try:
                a, b, p = params.split(',')
                a, b, p = int(a), int(b), int(p)
            except:
                die("| your parameters are not valid!!")
            if isPrime(p) and 0 < a < p and 0 < b < p and p.bit_length() == nbit:
                pr("| Send the parameters of second ECC y^2 = x^3 + cx + d like: c, d, q ")
                pr("| such that 0 < q - p <= 2022")
                params = sc()
                try:
                    c, d, q = params.split(',')
                    c, d, q = int(c), int(d), int(q)
                except:
                    die("| your parameters are not valid!!")
                if isPrime(q) and 0 < c < q and 0 < d < q and 0 < q - p <= 2022 and q.bit_length() == nbit:
                    G, H = random_point(a, b, p), random_point(c, d, q)
                    r, s = [getRandomRange(1, p-1) for _ in range(2)]
                    pr(f"| G is on first  ECC and G =", {G})
                    pr(f"| H is on second ECC and H =", {H})
                    U = multiply(G, r, a, p)
                    V = multiply(H, s, c, q)
                    pr(f"| r * G =", {U})
                    pr(f"| s * H =", {V})
                    pr("| Send r, s to get the flag: ")
                    rs = sc()
                    try:
                        u, v = rs.split(',')
                        u, v = int(u), int(v)
                    except:
                        die("| invalid input, bye!")
                    if u == r and v == s:
                        die("| You got the flag:", flag)
                    else:
                        die("| the answer is not correct, bye!")
                else:
                    die("| invalid parameters, bye!")
            else:
                die("| invalid parameters, bye!")
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()

```  
  
和上面的差不多，不过这次要输入两条曲线各自的   
，也限制了  
   
 也必须是大于   
，小于   
 或者   
 的，这样我们就不能用   
 或者是   
 这样去构造奇异曲线   
了，那就还是用TinyECC那边的smartattack叭，找到一条奇异曲线，然后设   
，再改变合适的系数使得   
 是光滑的（前面是变   
，这里是变   
，都大差不差的），这样离散对数好求。  
  
下面是一组示例  
```
q = 730750818665451459112596905638433048232067472077
aq = 3
bq = 481
Eq = EllipticCurve(GF(q), [aq,bq])

factor(Eq.order())                                                                                                
2^2 * 3 * 167 * 193 * 4129 * 882433 * 2826107 * 51725111 * 332577589 * 10666075363


```  
```
p = 730750818665451459112596905638433048232067471723 
ap = 425706413842211054102700238164133538302169176474 
bp = 203362936548826936673264444982866339953265530166
q = 730750818665451459112596905638433048232067472077
aq = 3
bq = 481

```  
```
from random import getrandbits

# params from http://www.monnerat.info/publications/anomalous.pdf
D = 11
j = -2**15

def anom_curve():
    m = 257743850762632419871495
    p = (11*m*(m + 1)) + 3
    a = (-3*j * inverse_mod((j - 1728), p)) % p
    b = (2*j * inverse_mod((j - 1728), p)) % p
    E = EllipticCurve(GF(p), [a,b])
    G = E.gens()[0]
    return p, a, b, E, G

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)


p = 730750818665451459112596905638433048232067471723 
ap = 425706413842211054102700238164133538302169176474 
bp = 203362936548826936673264444982866339953265530166

Ep = EllipticCurve(GF(p), [ap,bp])
G = Ep(126552689249226752349356206494226396414163660811, 559777835342379827315577715664975494598512818777)
rG = Ep(190128385937465835164338802317889165657442536853, 604514027124204305317929024826237325074492980218)

print(SmartAttack(G,rG,p))

q = 730750818665451459112596905638433048232067472077
aq = 3
bq = 481
Eq = EllipticCurve(GF(q), [aq,bq])

H = Eq(284866865619833057500909264169831974815120720320, 612322665682105897045018564282609259776516527853)
sH = Eq(673590124165798818844330235458561515292416807353, 258709088293250578320930080839442511989120686226)

print(H.discrete_log(sH))

```  
  
flag: CCTF{Pl4yIn9_Wi7H_ECC_1Z_liK3_pLAiNg_wiTh_Fir3!!}  
  
PS：感觉这两道题也可以控制参数使得两条曲线的阶都是比较光滑的，然后再解离散对数？  
- ## DOUBLE MIFF  
  
POINTS：217  
  
考点：椭圆曲线与丢番图方程  
```
from Crypto.Util.number import *
from secret import a, b, p, P, Q
from flag import flag

def onmiff(a, b, p, G):
    x, y = G
    return (a*x*(y**2 - 1) - b*y*(x**2 - 1)) % p == 0

def addmiff(X, Y):
    x_1, y_1 = X
    x_2, y_2 = Y
    x_3 = (x_1 + x_2) * (1 + y_1*y_2) * inverse((1 + x_1*x_2) * (1 - y_1*y_2), p) % p
    y_3 = (y_1 + y_2) * (1 + x_1*x_2) * inverse((1 + y_1*y_2) * (1 - x_1*x_2), p) % p
    return (x_3, y_3)


l = len(flag) // 2
m1, m2 = bytes_to_long(flag[:l]), bytes_to_long(flag[l:])

assert m1 < (p // 2) and m2 < (p // 2)
assert onmiff(a, b, p, P) and onmiff(a, b, p, Q)
assert P[0] == m1 and Q[0] == m2

print(f'P + Q = {addmiff(P, Q)}')
print(f'Q + Q = {addmiff(Q, Q)}')
print(f'P + P = {addmiff(P, P)}')
P + Q = (540660810777215925744546848899656347269220877882, 102385886258464739091823423239617164469644309399)
Q + Q = (814107817937473043563607662608397956822280643025, 961531436304505096581595159128436662629537620355)
P + P = (5565164868721370436896101492497307801898270333, 4969213281060625285080264123281718864612235

```  
  
根据题目我们有曲线   
，其中曲线参数   
 均未知，但是我们有   
，  
 总是要恢复的叭，需要用到给出的三个点。那么通过这三个点，我们有等式   
，我们设   
，那么我们有  
  
  
  
两式相减我们有  
  
  
同理，由   
 坐标的计算公式我们可以得到  
  
  
两个模   
 同余   
 式子，我们求一个   
 就能获取   
 的一个倍数了，分解一下应该就能获取素数   
。  
  
回到曲线的式子   
，对于两个未知数，emmm，我们给他搞成一个先 ，故而有  
  
  
于是只需要一个点我们就能知道   
，换一换也有  
  
  
我们设   
，那么根据加法规则，我们有  
  
  
  
两式相乘，我们有  
  
  
于是我们有  
  
  
因为   
，于是我们设   
，则有   
  
于是我们有   
，解一手二次方程，  
 ，我们就能够拿到   
 啦，同理也可以这么去拿  
，然后就能恢复 flag了。  
```
#!/usr/bin/env python3
from Crypto.Util.number import isPrime, long_to_bytes
from math import gcd

x1, y1 = (540660810777215925744546848899656347269220877882, 102385886258464739091823423239617164469644309399)
x2, y2 = (814107817937473043563607662608397956822280643025, 961531436304505096581595159128436662629537620355)
x3, y3 = (5565164868721370436896101492497307801898270333, 496921328106062528508026412328171886461223562143)
num1 = (1 + x1 ** 2) * (1 - y1 ** 2) * (x2 + x3) * (1 + y2 * y3) - 2 * x1 * (1 + y1 ** 2) * (1 + x2 * x3) * (1 - y2 * y3)
num2 = (1 + y1 ** 2) * (1 - x1 ** 2) * (y2 + y3) * (1 + x2 * x3) - 2 * y1 * (1 + x1 ** 2) * (1 + y2 * y3) * (1 - x2 * x3)
pmult = gcd(num1, num2)
print(pmult)
# sage: factor(9132984636916703206790144643146359197427822823096)
# 2^3 * 1141623079614587900848768080393294899678477852887

p=1141623079614587900848768080393294899678477852887
def recover_half(x, y):
    k = y * (x ** 2 - 1) * pow(x * (y ** 2 - 1), -1, p) % p
    l = pow(4 * k * pow(x * y, -1, p), (p + 1) // 4, p)
    D = (l ** 2 + 4) % p
    sqrtD = pow(D, (p + 1) // 4, p)
    for i in (-1, 1):
        for j in (-1, 1):
            num = (i * l + j * sqrtD) * pow(2, -1, p) % p
            text = long_to_bytes(num)
            if b'CCTF{' in text or b'}' in text:
                return text

first_half = recover_half(x3, y3)
second_half = recover_half(x2, y2)
flag = (first_half + second_half).decode()
print(flag)
#CCTF{D39enEr47E_ECC_4TtaCk!_iN_Huffs?}

```  
- ## ECCHIMERA  
  
POINTS：271  
  
考点：椭圆曲线离散对数，smart attack，pohlig-hellman  
```
from sage.all import *
from flag import flag


n = 43216667049953267964807040003094883441902922285265979216983383601881964164181
U = 18230294945466842193029464818176109628473414458693455272527849780121431872221
V = 13100009444194791894141652184719316024656527520759416974806280188465496030062
W = 5543957019331266247602346710470760261172306141315670694208966786894467019982

flag = flag.lstrip(b'CCTF{').rstrip(b'}')
s = int(flag.hex(), 16)
assert s < n

E = EllipticCurve(Zmod(n), [0, U, 0, V, W])
G = E(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)

print(f'G = {G}')
print(f's * G = {s * G}')

```  
  
n可以分解  
```
n = 43216667049953267964807040003094883441902922285265979216983383601881964164181
U = 18230294945466842193029464818176109628473414458693455272527849780121431872221
V = 13100009444194791894141652184719316024656527520759416974806280188465496030062
W = 5543957019331266247602346710470760261172306141315670694208966786894467019982

E = EllipticCurve(Zmod(n), [0, U, 0, V, W])
G = E(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)
sG = E(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)

p = 190116434441822299465355144611018694747
q = 227316839687407660649258155239617355023

assert p * q == n

# P and Q curves
Ep = EllipticCurve(GF(p), [0, ZZ(U % p), 0, ZZ(V % p), ZZ(W % p)])
Eq = EllipticCurve(GF(q), [0, ZZ(U % q), 0, ZZ(V % q), ZZ(W % q)])

kp = Ep.order()
kq = Eq.order()

```  
  
第一部分  
  
kp=p，smart attack  
  
第二部分  
  
sage: factor(kq) 2^4 * 3 * 13 * 233 * 4253 * 49555349 * 7418313402470596923151  
  
但是直接discrete_log好像不行，这里选择放弃因子 3（Gq的阶没有因子3） 和 最大的 7418313402470596923151（数值太大） ，然后手撸一个pohlig hellman （也可以调参调用discrete_log，但好慢，感觉不如手撸）  
```
primes = [2^4,13, 233, 4253, 49555349] #don't use 3 and last one, cuz last one is too big, and 3 is not Gq's order's factor
dlogs = []

for fac in primes:
    print(fac)
    t = int(Gq.order()) // int(fac)
    dlog = (t*Gq).discrete_log(t*sGq) #discrete_log(t*sGq, t*Gq, operation="+")
    dlogs += [dlog]
    #print("factor: "+str(fac)+", Discrete Log: "+str(dlog)) #calculates discrete logarithm for each prime order

q_secret = crt(dlogs, primes)

```  
  
最后再crt一下就好了  
```
#!/usr/bin/env sage
from Crypto.Util.number import *

n = 43216667049953267964807040003094883441902922285265979216983383601881964164181
U = 18230294945466842193029464818176109628473414458693455272527849780121431872221
V = 13100009444194791894141652184719316024656527520759416974806280188465496030062
W = 5543957019331266247602346710470760261172306141315670694208966786894467019982

E = EllipticCurve(Zmod(n), [0, U, 0, V, W])
G = E(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)
sG = E(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)

p = 190116434441822299465355144611018694747
q = 227316839687407660649258155239617355023

assert p * q == n

# P curve
Ep = EllipticCurve(GF(p), [0, ZZ(U % p), 0, ZZ(V % p), ZZ(W % p)])
Eq = EllipticCurve(GF(q), [0, ZZ(U % q), 0, ZZ(V % q), ZZ(W % q)])

kp = Ep.order()
kq = Eq.order()

Gp = Ep(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)
Gq = Eq(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)

sGp = Ep(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)
sGq = Eq(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)

print(Gp.order())
print(Gq.order())

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

primes = [2^4, 13, 233, 4253, 49555349] #don't use 3 and last one
dlogs = []

for fac in primes:
    t = int(Gq.order()) // int(fac)
    dlog = (t*Gq).discrete_log(t*sGq) #discrete_log(t*sGq, t*Gq, operation="+")
    dlogs += [dlog]
    #print("factor: "+str(fac)+", Discrete Log: "+str(dlog)) #calculates discrete logarithm for each prime order


p_secret = SmartAttack(Gp,sGp,p)
q_secret = crt(dlogs, primes)  #9092500866606561 #discrete_log(sGq, Gq, ord=Gq.order(), bounds=2^4 * 13 * 233 * 4253 * 49555349, operation="+")

print(p_secret, q_secret)
flag = long_to_bytes(int(crt([p_secret, q_secret], [Gp.order(), Gq.order() // 7418313402470596923151])))
print(flag)

```  
  
flag:CCTF{m1X3d_VeR5!0n_oF_3Cc!}  
  
主要因为   
 ，所以我们才能解出flag。  
- ## ROHALD  
  
POINTS：180  
  
考点：椭圆曲线、Edwards Curve、Montgomery、Weierstrass  
```
#!/usr/bin/env sage

from Crypto.Util.number import *
from secret import flag, Curve

def ison(C, P):
    c, d, p = C
    u, v = P
    return (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) % p == 0

def teal(C, P, Q):
    c, d, p = C
    u1, v1 = P
    u2, v2 = Q
    assert ison(C, P) and ison(C, Q)
    u3 = (u1 * v2 + v1 * u2) * inverse(c * (1 + d * u1 * u2 * v1 * v2), p) % p
    v3 = (v1 * v2 - u1 * u2) * inverse(c * (1 - d * u1 * u2 * v1 * v2), p) % p
    return (int(u3), int(v3))

def peam(C, P, m):
    assert ison(C, P)
    c, d, p = C
    B = bin(m)[2:]
    l = len(B)
    u, v = P
    PP = (-u, v)
    O = teal(C, P, PP)
    Q = O
    if m == 0:
        return O
    elif m == 1:
        return P
    else:
        for _ in range(l-1):
            P = teal(C, P, P)
        m = m - 2**(l-1)
        Q, P = P, (u, v)
        return teal(C, Q, peam(C, P, m))

c, d, p = Curve

flag = flag.lstrip(b'CCTF{').rstrip(b'}')
l = len(flag)
lflag, rflag = flag[:l // 2], flag[l // 2:]

s, t = bytes_to_long(lflag), bytes_to_long(rflag)
assert s < p and t < p

P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)

print(f'ison(C, P) = {ison(Curve, P)}')
print(f'ison(C, Q) = {ison(Curve, Q)}')

print(f'P = {P}')
print(f'Q = {Q}')

print(f's * P = {peam(Curve, P, s)}')
print(f't * Q = {peam(Curve, Q, t)}')

ison(C, P) = True
ison(C, Q) = True
P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
s * P = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
t * Q = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933)

```  
  
首先还是要获取椭圆曲线的参数   
  
对于   
 的获取，由于我们知道四个点   
  
根据曲线我们有   
  
所以如果有两个点，我们就能够得出   
  
  
  
两式相减我们有   
  
于是   
 ，可求  
  
有了   
，我们就能求出   
 了，  
  
同理我们用另外两个点就能够搞出   
 了，然后 gcd一下，再factor一下，就能够求出   
了。  
  
有了  
，根据   
 也能求出   
 了，从而也能求出   
 了。  
```
from math import gcd

def ison(C, P):
    """    Verification points are on the curve    """
    c, d, p = C
    u, v = P
    return (u**2 + v**2 - cc * (1 + d * u**2*v**2)) % p == 0

def a_and_b(u1,u2,v1,v2):
    """    Helper function used to simplify calculations    """
    a12 = u1**2 - u2**2 + v1**2 - v2**2
    b12 = u1**2 * v1**2 - u2**2 * v2**2
    return a12, b12

def find_modulus(u1,u2,u3,u4,v1,v2,v3,v4):
    """    Compute the modulus from four points    """
    a12, b12 = a_and_b(u1,u2,v1,v2)
    a13, b13 = a_and_b(u1,u3,v1,v3)
    a23, b23 = a_and_b(u2,u3,v2,v3)
    a24, b24 = a_and_b(u2,u4,v2,v4)

    p_almost = gcd(a12*b13 - a13*b12, a23*b24 - a24*b23)

    for i in range(2,1000):
        if p_almost % i == 0:
            p_almost = p_almost // i

    return p_almost

def c_sq_d(u1,u2,v1,v2,p):
    """    Helper function to computer c^2 d    """
    a1,b1 = a_and_b(u1,u2,v1,v2)
    return a1 * pow(b1,-1,p) % p

def c(u1,u2,v1,v2,p):
    """    Compute c^2, d from two points and known modulus    """
    ccd = c_sq_d(u1,u2,v1,v2,p)
    cc = (u1**2 + v1**2 - ccd*u1**2*v1**2) % p
    d = ccd * pow(cc, -1, p) % p
    return cc, d


P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
sP = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
tQ = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933)

u1, v1 = P
u2, v2 = Q
u3, v3 = sP
u4, v4 = tQ

p = find_modulus(u1,u2,u3,u4,v1,v2,v3,v4)
cc, d = c(u1,u2,v1,v2,p)

C = cc, d, p
assert ison(C, P)
assert ison(C, Q)
assert ison(C, sP)
assert ison(C, tQ)

print(f'Found curve parameters')
print(f'p = {p}')
print(f'c^2 = {cc}')
print(f'd = {d}')

# Found curve
# p = 903968861315877429495243431349919213155709
# cc = 495368774702871559312404847312353912297284
# d = 540431316779988345188678880301417602675534

```  
  
脚本来自https://blog.cryptohack.org/cryptoctf2021-hard#rohald（注意   
 开根的时候有两个解，最后解flag的时候都要尝试一下）  
  
然后我们得转化这个椭圆曲线的形式，从Edwards Curve 转到 Montgomery形式最后变成Weierstrass形式，然后会发现这条曲线的阶光滑，直接调用 sagemath 的 discrete_log 就能进行求解。  
  
  
  
  
Edwards Curve to   
   
  
to Montgomery   
   
  
to Weierstrass   
   
```
def to_elliptic_2(P, p, c, d):
    Zp = Zmod(p)
    x, y = P
    x, y = Zp(x), Zp(y)
    c, d = Zp(c), Zp(d)
    x, y = x / c , y / c 
    d = d * c ** 4
    
    # Montgomery
    u = (1 + y) / (1 - y)
    v = (2 * (1+y)) / (x * (1-y))
    B = 1 / (1-d)
    A = 2 * (1+d) / (1-d)

    # Weierstrass
    x = u / B + A / (3*B)
    y = v / B
    a = (3 - A**2) / (3 * B**2)
    b = (2 * A**3 - 9*A) / (27 * B**3)
    return (x, y), a, b

p = 903968861315877429495243431349919213155709
c = 662698094423288904843781932253259903384619
d = 540431316779988345188678880301417602675534
P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
S = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
T = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933)

P1, a, b = to_elliptic_2(P, p, c, d)
Q1, a, b = to_elliptic_2(Q, p, c, d)
S1, a, b = to_elliptic_2(S, p, c, d)
T1, a, b = to_elliptic_2(T, p, c, d)

EC = EllipticCurve(Zmod(p), [a, b])
P1 = EC(P1)
Q1 = EC(Q1)
S1 = EC(S1)
T1 = EC(T1)

s = P1.discrete_log(S1)
t = Q1.discrete_log(T1)
print(s)
print(t)

```  
  
脚本来自 https://zhuanlan.zhihu.com/p/399487467  
- ## ROBERT  
  
POINTS：194  
  
考点：carmichael_lambda  
```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+   hi all, all cryptographers know that fast calculation is not easy! +
+   In each stage for given integer m, find number n such that:        +
+   carmichael_lambda(n) = m, e.g. carmichael_lambda(2021) = 966       +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
| send an integer n such that carmichael_lambda(n) = 52: 

```  
  
给出一个值   
，求   
 的   
，一个想法是通过查找   
 的因子   
， 如果   
 为素数，并且满足   
，那么我们有   
```
def reverse_lambda(n):
    for x in divisors(n):
        for y in divisors(n):
            if lcm(x, y) == n and is_prime(x + 1) and is_prime(y + 1):
                return (x + 1) * (y + 1)

```  
- ## TRUNC  
  
POINTS：334  
  
考点：Signature forgery  
```
#!/usr/bin/env python3

from Crypto.Util.number import *
from hashlib import sha256
import ecdsa
from flag import FLAG

E = ecdsa.SECP256k1
G, n = E.generator, E.order

cryptonym = b'Persian Gulf'

def keygen(n, G):
    privkey = getRandomRange(1, n-1)
    pubkey = privkey * G
    return (pubkey, privkey)

def sign(msg, keypair):
    nbit, dbit = 256, 25
    pubkey, privkey = keypair
    privkey_bytes = long_to_bytes(privkey)
    x = int(sha256(privkey_bytes).hexdigest(), 16) % 2**dbit
    while True:
        k, l = [(getRandomNBitInteger(nbit) << dbit) + x for _ in '01']
        u, v = (k * G).x(), (l * G).y()
        if u + v > 0:
            break
    h = int(sha256(msg).hexdigest(), 16)
    s = inverse(k, n) * (h * u - v * privkey) % n
    return (int(u), int(v), int(s))

def verify(msg, pubkey, sig):
    if any(x < 1 or x >= n for x in sig):
        return False
    u, v, s = sig
    h = int(sha256(msg).hexdigest(), 16)
    k, l = h * u * inverse(s, n), v * inverse(s, n)
    X = (k * G + (n - l) * pubkey).x()
    return (X - u) % n == 0

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
    pr(border, " hi all, welcome to the high secure elliptic curve signature oracle!", border)
    pr(border, " Your mission is to sign the out cryptonym, try your best :)        ", border)
    pr(border*72)

    keypair = keygen(n, G)
    pubkey, privkey = keypair

    while True:
        pr("| Options: \n|\t[P]rint the pubkey \n|\t[S]ign \n|\t[V]erify \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 'p':
            pr("| pubkey =", pubkey.x(), pubkey.y())
        elif ans == 's':
            pr("| send your hex message to sign: ")
            msg = sc()
            try:
                msg = bytes.fromhex(msg)
            except:
                die("| your message is not valid! Bye!!")
            if msg == cryptonym:
                die('| Kidding me? Bye')
            msg = msg[:14]
            sig = sign(msg, keypair)
            pr("| sign =", sig)
        elif ans == 'v':
            pr("| send your hex message to verify: ")
            msg = sc()
            try:
                msg = bytes.fromhex(msg)
            except:
                die("| your message is not valid! Bye!!")
            pr("| send the signature separated with comma: ")
            sig = sc()
            try:
                sig = [int(s) for s in sig.split(',')]
            except:
                die("| your signature is not valid! Bye!!")
            if verify(msg, pubkey, sig):
                if msg == cryptonym:
                    die("| Good job! Congrats, the flag is:", FLAG)
                else:
                    pr("| your message is verified!!")
            else:
                die("| your signature is not valid! Bye!!")
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()

```  
  
可以被非预期，  
  
注意到验签函数：  
，其中  
 可控，验证   
  
若目标消息哈希为   
，我们构造任意消息哈希为   
，并且设   
，  
  
随后我们让服务端签名我们的消息，并得到签名   
，此时   
，该组   
能通过验证。  
  
那么我们在伪造签名时只要设   
，  
  
就会有   
，由上可知，该组   
 能通过验证。  
```
#!/usr/bin/env python3
from pwn import remote
from ecdsa import SECP256k1
from hashlib import sha256

n = SECP256k1.order
m1 = b'lol' # any other message is fine
m2 = b'Persian Gulf'
h1 = int(sha256(m1).hexdigest(), 16)
h2 = int(sha256(m2).hexdigest(), 16)
m = h2 * pow(h1, -1, n) % n
r = remote("02.cr.yp.toc.tf", 23010)
for _ in range(9):
    r.recvline()
r.sendline('s')
r.recvline()
r.sendline(m1.hex())
u1, v1, w1 = eval(r.recvline()[8:])
u2, v2, w2 = u1, v1 * m % n, w1 * m % n
for _ in range(5):
    r.recvline()
r.sendline('v')
r.recvline()
r.sendline(m2.hex())
r.recvline()
r.sendline(','.join(map(str, [u2, v2, w2])))
print(r.recvline().decode().strip().split()[-1])
r.close()

```  
  
CCTF{__ECC_Bi4seD_N0nCE_53ns3_LLL!!!}  
  
（PS：不过看着flag，估计要构造格，又非预期了，，，）  
- ## MY SIEVE  
  
POINTS：477  
  
考点：RSA  
```
enc = 17774316754182701043637765672766475504513144507864625935518462040899856505354546178499264702656639970102754546327338873353871389580967004810214134215521924626871944954513679198245322915573598165643628084858678915415521536126034275104881281802618561405075363713125886815998055449593678564456363170087233864817

-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB*QKBgQCkRgRCyTcSwlBKmERQV/BHkurS
5QnYz7Rm18OjxuuWT3A*Ueqzq7fHISey2NEEtral/*E7v2Dy59DYHoRAAouWQd03
ZYWnvU5mWoYRcpNmHIj8q*+FOtBWcCGzMZ8uxOxaV74vqqerjxyRI14rXZ+QOcNM
/TMM84h0rl/IKqqWsQIDAQAB
-----END PUBLIC KEY-----



```  
  
题目还给了一个msieve文件，里面有一个  
```
0x1dabd3bb8e99101030cd7094eb15dd525cb0f02065694604071c2a8b10228f30cc12d08fc9caa8d97c65ff481

```  
  
似乎是   
 的一个因子，  
  
且已经有了分解  
```
11
37517726695590864161261967849116722975727713562769161
41223455646589331474862018682296591762663841134030283

```  
  
注意到公钥文件里面有四个 *，是被“污染”的   
，  
  
这里一个想法是爆破一下，64**4 的复杂度，还好。但是好像最后也没结果。  
  
然后用一用非预期（如果   
 比较小的话），尝试在“子剩余系“下解密  
```
from Crypto.Util.number import *                                                                                  
p = 37517726695590864161261967849116722975727713562769161
q = 41223455646589331474862018682296591762663841134030283
N = p*q
phi = (p-1)*(q-1)
e = 0x10001
d = pow(e,-1,phi)
enc = 17774316754182701043637765672766475504513144507864625935518462040899856505354546178499264702656639970102754546327338873353871389580967004810214134215521924626871944954513679198245322915573598165643628084858678915415521536126034275104881281802618561405075363713125886815998055449593678564456363170087233864817                            
flag = long_to_bytes(pow(enc,d,N))
print(flag) 

# b'CCTF{l34Rn_WorK_bY__Msieve__A5aP}'

```  
  
成了！  
  
那如果 flag 比较大怎么办？  
  
（PS：  
  
赛后没有被“污染”的公钥文件公布了，发现  
```
a='''-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkRgRCyTcSwlBKmERQV/BHkurT5QnYz7Rm18OjxuuWT3AhUeqzq7fHISey2NEEtral/jE7v2Dy59DYHoRAAouWQd02ZYWnvU5mWoYRcpNmHIj8qk+FOtBWcCGzMZ8uxOxaV74vqqerjxyRI14rXZ+QOcNL/TMM84h0rl/IKqqWsQIDAQAB-----END PUBLIC KEY-----'''
b = '''-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB*QKBgQCkRgRCyTcSwlBKmERQV/BHkurS5QnYz7Rm18OjxuuWT3A*Ueqzq7fHISey2NEEtral/*E7v2Dy59DYHoRAAouWQd03ZYWnvU5mWoYRcpNmHIj8q*+FOtBWcCGzMZ8uxOxaV74vqqerjxyRI14rXZ+QOcNM/TMM84h0rl/IKqqWsQIDAQAB-----END PUBLIC KEY-----'''

for i in range(len(a)):
 if a[i] != b[i]:
  print(i,a[i],b[i])

59 i *
90 T S
111 h *
133 j *
155 2 3
178 k *
220 L M

```  
  
发现除了 * 处，还有其他地方也不一样，，emmm，不是很懂出题人啥意思。  
- ## DORSA  
  
POINTS：450  
  
考点：RSA  
```
#!/usr/bin/env python3

from Crypto.Util.number import *
from math import gcd
from flag import FLAG

def keygen(nbit, dbit):
    assert 2*dbit < nbit
    while True:
        u, v = getRandomNBitInteger(dbit), getRandomNBitInteger(nbit // 2 - dbit)
        p = u * v + 1
        if isPrime(p):
            while True:
                x, y = getRandomNBitInteger(dbit), getRandomNBitInteger(nbit // 2 - dbit)
                q = u * y + 1
                r = x * y + 1
                if isPrime(q) and isPrime(r):
                    while True:
                        e = getRandomNBitInteger(dbit)
                        if gcd(e, u * v * x * y) == 1:
                            phi = (p - 1) * (r - 1)
                            d = inverse(e, phi)
                            k = (e * d - 1) // phi
                            s = k * v + 1
                            if isPrime(s):
                                n_1, n_2 = p * r, q * s
                                return (e, n_1, n_2)

def encrypt(msg, pubkey):
    e, n = pubkey
    return pow(msg, e, n)

nbit, dbit = 1024, 256

e, n_1, n_2 = keygen(nbit, dbit)

FLAG = int(FLAG.encode("utf-8").hex(), 16)

c_1 = encrypt(FLAG, (e, n_1))
c_2 = encrypt(FLAG, (e, n_2))

print('e =', e)
print('n_1 =', n_1)
print('n_2 =', n_2)

print('enc_1 =', c_1)
print('enc_2 =', c_2)

e = 93546309251892226642049894791252717018125687269405277037147228107955818581561
n_1 = 36029694445217181240393229507657783589129565545215936055029374536597763899498239088343814109348783168014524786101104703066635008905663623795923908443470553241615761261684865762093341375627893251064284854550683090289244326428531870185742069661263695374185944997371146406463061296320874619629222702687248540071
n_2 = 29134539279166202870481433991757912690660276008269248696385264141132377632327390980628416297352239920763325399042209616477793917805265376055304289306413455729727703925501462290572634062308443398552450358737592917313872419229567573520052505381346160569747085965505651160232449527272950276802013654376796886259
enc_1 = 4813040476692112428960203236505134262932847510883271236506625270058300562795805807782456070685691385308836073520689109428865518252680199235110968732898751775587988437458034082901889466177544997152415874520654011643506344411457385571604433702808353149867689652828145581610443408094349456455069225005453663702
enc_2 = 2343495138227787186038297737188675404905958193034177306901338927852369293111504476511643406288086128052687530514221084370875813121224208277081997620232397406702129186720714924945365815390097094777447898550641598266559194167236350546060073098778187884380074317656022294673766005856076112637129916520217379601

```  
  
根据 题目，我们有  
  
  
其中   
  
注意到  
  
  
所以   
 有可能会在   
 的连分数上（具体的关系没有推，做题的时候可以本地测几组数据）  
  
（这里假设   
 了，但是也不一定是 1 叭，但也应该不大，可以小爆破一下？）  
  
有了   
 后，我们有  
  
  
  
有这两条同余式，我们能恢复   
 大约 1024bit的信息，即   
。  
  
另外  
  
  
由于   
 大约有   
 比特，我们首先设   
，  
 值大约使得我们的   
 和   
 一个数量级，然后再在小范围爆破一下即可恢复   
，从而解密获得   
  
exp，来自https://blog.cryptohack.org/cryptoctf2021-hard#dorsa  
```
from tqdm import 
from Crypto.Util.number import *

e = 93546309251892226642049894791252717018125687269405277037147228107955818581561
n_1 = 36029694445217181240393229507657783589129565545215936055029374536597763899498239088343814109348783168014524786101104703066635008905663623795923908443470553241615761261684865762093341375627893251064284854550683090289244326428531870185742069661263695374185944997371146406463061296320874619629222702687248540071
n_2 = 29134539279166202870481433991757912690660276008269248696385264141132377632327390980628416297352239920763325399042209616477793917805265376055304289306413455729727703925501462290572634062308443398552450358737592917313872419229567573520052505381346160569747085965505651160232449527272950276802013654376796886259
enc_1 = 4813040476692112428960203236505134262932847510883271236506625270058300562795805807782456070685691385308836073520689109428865518252680199235110968732898751775587988437458034082901889466177544997152415874520654011643506344411457385571604433702808353149867689652828145581610443408094349456455069225005453663702
enc_2 = 2343495138227787186038297737188675404905958193034177306901338927852369293111504476511643406288086128052687530514221084370875813121224208277081997620232397406702129186720714924945365815390097094777447898550641598266559194167236350546060073098778187884380074317656022294673766005856076112637129916520217379601

c = continued_fraction(Integer(n_2) / Integer(n_1))

for i in tqdm(range(150)):
    k = c.numerator(i)
    x = c.denominator(i)
    if GCD(e, k) != 1:
        continue
    phi_e = inverse(e - k, e)
    phi_ex = crt(phi_e, 0, e, x)
    ex = e * x // GCD(e, x)

    st = phi_ex + (n_1 // ex) * ex - 100 * ex
    for j in range(200):
        if GCD(e, st) != 1:
            st += ex
            continue 
        d_1 = inverse(e, st)
        flag = long_to_bytes(pow(enc_1, d_1, n_1))
        if b"CCTF" in flag:
            print(flag)
        st += ex
        
b'CCTF{__Lattice-Based_atT4cK_on_RSA_V4R1aN75!!!}'

```  
  
(PS：看这flag，又非预期了似乎。。。。)  
- ## POLISH  
  
POINTS：477  
  
考点：RSA，Partial Key Exposure Attack  
```
m = bytes_to_long(flag)

e = 65537

n = p * q
  = 40246250034008312612597372763167482121403594640959033279625274444300931999548988739160328671767018778652394885185401059130887869211330599272113849088780129624581674441314938139267245340401649784020787977993123159165051168187958742107

d = 0b1[REDACTED]00001101110000010101000000101110000111101011011101111111000011110101111000100001011100001111011000010101010010111100000011000101000001110001111100001011001100010001100000011100001101101100011101000001010001100000101000001

c = pow(x**2 + m + y, e, n)
  = 28505561807082805875299833176536442119874596699006698476186799206821274572541984841039970225569714867243464764627070206533293573878039612127495688810559746369298640670292301881186317254368892594525084237214035763200412059090430060075

x**2 * (y - 146700196613209180651680280746469710064760660116352037627587109421827052580531) + y**2 * (x - 146700196613209180651680280746469710064760660116352037627587109421827052580531) = 27617741006445293346871979669264566397938197906017433294384347969002810245774095080855953181508639433683134768646569379922750075630984038851158577517435997971553106764846655038664493024213691627948571214899362078353364358736447296943

```  
  
根据题目，我们已知   
，和一个丢番图方程。显然获得flag，除了把 RSA 解密，我们还得解这个丢番图方程获取   
  
那么，先看看怎么解这个丢番图方程，我们有  
  
  
我们设   
，上式整理一下有  
  
  
替换后有  
  
  
  
  
  
可以看到   
 应该是   
 的一个因子，所以我们可以尝试一下分解   
？因为知道   
，然后就能获得   
 了。  
  
这时会发现  
  
  
那么问题又回到分解   
 上来了。  
  
那么这里泄露了私钥   
 的低位，这里尝试用coppersmith对其进行分解  
  
考虑到   
 的大小，如果  
 数量级差不多，平均分了   
 的比特长度，那么除去已知的   
 低位，我们大约还剩   
个低位，   
 ，那么应该选择   
  
但是这里考虑道   
 是   
 的一个因子，  
，  
 大约为   
，  
，如果   
 的数量级差不多，那么应该   
 都大约是   
，那么   
 应该是   
 这样子的分布。于是我们这里使用参数   
  
（PS：由于e很大，所以个人PC挺难跑的，这里解题者是使用了20cores的计算机多线程去跑的。。。。）  
  
exp来自：https://blog.cryptohack.org/cryptoctf2021-hard#polish  
```
# Part 1 : Factorization of n, written by rbtree
# Also, multiprocess the code below with multiple cores for shorter computation time

e = 65537
n = 40246250034008312612597372763167482121403594640959033279625274444300931999548988739160328671767018778652394885185401059130887869211330599272113849088780129624581674441314938139267245340401649784020787977993123159165051168187958742107

mod = 2^221
d_low = 0b00001101110000010101000000101110000111101011011101111111000011110101111000100001011100001111011000010101010010111100000011000101000001110001111100001011001100010001100000011100001101101100011101000001010001100000101000001

def get_p(p_low):
    F.<z> = PolynomialRing(Zmod(n))

    f = mod * z + p_low
    f = f.monic()
    res = f.small_roots(beta=0.33, epsilon=0.05)

    if len(res) > 0:
        print(res)
        return gcd(int(f(res[0])),int(n))
    return None

R.<x> = PolynomialRing(ZZ)
from tqdm import *
for k in tqdm(range(1, e+1)):
    cands = [1]
    f = k * x^2 + (e*d_low - k*n - k - 1) * x + k * n

    cands = [1]
    for i in range(1, 509):
        new_cands = []
        for v in cands:
            if int(f(v)) % 2^(i+1) == 0:
                new_cands.append(v)
            if int(f(v + 2^i)) % 2^(i+1) == 0:
                new_cands.append(v + 2^i)
        
        cands = new_cands
        if len(new_cands) == 0:
            print("break", i)
            break

    #print(k)
    #print(cands)

    ret = None
    for v1 in cands:
        for v2 in cands:
            if v1 * v2 % mod != n % mod:
                continue
            ret = get_p(v1)
            break
        if ret:
            print(ret)


```  
  
有了   
 后，我们获取   
，因为之前   
，解一个方程我们获取   
，然后就能解密密文得到   
 了。  
```
# Part 2 : Calculating the Flag

def inthroot(a, n):
    return a.nth_root(n, truncate_mode=True)[0]

n = 40246250034008312612597372763167482121403594640959033279625274444300931999548988739160328671767018778652394885185401059130887869211330599272113849088780129624581674441314938139267245340401649784020787977993123159165051168187958742107

a = 146700196613209180651680280746469710064760660116352037627587109421827052580531
b = 27617741006445293346871979669264566397938197906017433294384347969002810245774095080855953181508639433683134768646569379922750075630984038851158577517435997971553106764846655038664493024213691627948571214899362078353364358736447296943

assert n == 4 * a * a * a + b

# from rbtree's code with partial exposure attack on d
p = 893797203302975694226187727100454198719976283557332511256329145998133198406753
q = n // p

u = p - 2 * a
v = (a * u * u + b) // (u + 2 * a)
dif = inthroot(Integer(u * u - 4 * v), 2)

x = (u + dif) // 2
y = (u - dif) // 2

e = 65537 

c = 28505561807082805875299833176536442119874596699006698476186799206821274572541984841039970225569714867243464764627070206533293573878039612127495688810559746369298640670292301881186317254368892594525084237214035763200412059090430060075

d = inverse(e, (p-1) * (q-1))

res = pow(c, d, n)

print(long_to_bytes(res - x * x - y))
print(long_to_bytes(res - y * y - x))

```  
  
flag:CCTF{Par7ial_K3y_Exp0sure_At7ack_0n_L0w_3xP_RSA}  
  
（PS：看这flag，  
 也不小啊，是不是放错了，，，，，）  
  
         
