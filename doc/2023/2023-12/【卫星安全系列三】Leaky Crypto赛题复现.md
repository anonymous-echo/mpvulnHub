#  【卫星安全系列三】Leaky Crypto赛题复现   
原创 Tover.  山石网科安全技术研究院   2023-12-12 11:29  
  
一道卫星上AES侧信道攻击的题目，主要利用AES T-表的Cache缓存碰撞实施攻击。  
## 题目描述  
  
题目文件：  
```
https://github.com/ADDVulcan/ADDVulcan/tree/master/Payload%20Modules/Leaky%20Crypto

```  
  
题目有两个文件，Readme.txt文件是题目描述，大概意思是题目使用AES-128的ECB模式和前6字节为97ca6080f575的密钥加密了flag，密文是：  
```
7972c157dad7b858596ecdb798877cc4ed4b03d6822295954e69b7ecebb704af08c054a03a374f8bdaa18ff16ba09be2b6b25f1ef73ef80111646de84cd3af2514501e056889e95c680f7d199b6531e9dd6ee599aeb23835327e6e853a9a40a9f405bd1443e014363ea46631582b97c3d3f83f4e1101da2557f9b03808a61968

```  
  
test.txt文件是题目附件，其中给了100000个明文和其对应的加密时间，如：  
```
2c86f81fdc568d631c9dd0a075ec2a35,10776
5e7b2322d8a2dabd86884d42de3748c8,10704
3ebac48a8c3b0a3b552c385eafc7f99a,10776
54f865a9cc7a3a1bcf68bad09d0b699a,10704
... ...

```  
  
在Readme.txt文件中还有一点提示，最有用的是解这题需要用到侧信道攻击（Side Channel Attacks）。  
  
搜集一下关于AES侧信道的资料，可以翻到有一种对AES的T-表进行侧信道攻击，恰好可以用来攻击这道题目。  
## AES、T-Table和缓存碰撞  
  
在了解攻击前，需要知道一点前置知识。  
  
AES的详细流程非常复杂，这里不多说，建议先去参考教科书或CTF Wiki学习学习。  
  
简要来说的话，AES主要有以下4个操作：  
- 轮密钥加，AddRoundKey  
  
- 字节替换，SubBytes  
  
- 行移位，ShiftRows  
  
- 列混淆，MixColumns  
  
在明文P被输进AES算法后，按照顺序执行  
```
P -> AddRoundKey ->
SubBytes -> ShiftRows -> MixColumns -> AddRoundKey ->
... (9 Rounds) ...
SubBytes -> ShiftRows -> MixColumns -> AddRoundKey ->
SubBytes -> ShiftRows -> MixColumns -> C

```  
  
其中的SubBytes -> ShiftRows -> MixColumns -> AddRoundKey被称作一轮（Round）。  
  
以上只是教科书版本的AES，实际应用时，为了加速AES的运算速度会做一些优化，比如这里的查表法。  
  
首先SubBytes和ShiftRows 是相互独立的，即它们的操作顺序可以替换，这样的话一轮的操作就可以变成  
```
ShiftRows -> SubBytes -> MixColumns -> AddRoundKey

```  
  
然后SubBytes中的操作是通过查S-Box替换字节，MixColumns大概是一个线性的加法（异或），如果先用线性加法的系数和S-Box做预运算，生成一个叫“T-表”的表，那么在加密/解密时通过查T-表而不是S-Box，就可以省去乘法操作，从而加快运算时间。  
  
另外，ShiftRows里面的移位顺序也是固定的，所以把这个顺序写死的话，也可以节省移位操作消耗的时间。  
  
假设上一轮的输出中对应的每个字节是  
，假设在这轮的中MixColumns后的4个块为  
，优化后就大概可以得到：  
  
  
其中  
就是T-表的4张表，这里因为篇幅原因我省略了很多的细节，比如  
是怎样生成的，想了解更多的话可以去参考相关的文献。  
  
可以看到在  
的生成过程中，都会查  
表各一次，如果在  
和  
的生成过程中，某个表  
的输入都一样，那么就会触发计算机中的一个缓存机制（Cache Hits）。  
  
缓存（Cache）大概意思是，计算机为了提高CPU的运算效率，会把常用的数据放在CPU的缓存中，如果下一次需要用到这个数据，只需要在里CPU很近的缓存中拿这个数据即可，而不用到更远/更慢的内存或外存中获取。  
  
假设在  
生成时  
的输入是  
，那么计算机就会把  
中  
位置的数据放进缓存中。  
- 如果在  
生成时  
的输入恰好是  
，就会触发一次Cache Hits，CPU只需直接拿缓存中的对应数据。  
  
- 如果在  
生成时  
的输入不是  
，就会触发一次Cache Misses，CPU需要从更远的内存中获取这个数据，然后（可能会）用这个数据覆盖缓存中对应位置的数据。  
  
显然Cache Hits时的运算会比Cache Misses时的运算更快。  
  
PS：以上只是对教科书版本的缓存的简单介绍，实际应用时，不同的CPU的缓存设计都不尽相同，更别说卫星上的，在实际攻击时我也发现题目使用的缓存有一些特别的机制。  
## AES缓存碰撞攻击  
  
回到题目，题目给了多组明文和对应的加密时间，那么就可以使用这个时间去分辨哪一组明文的加密触发了Cache Hits碰撞，然后利用这个碰撞信息去恢复密钥。  
  
问题是，如何从碰撞中恢复密钥？  
  
如果只看优化版本AES的第一轮操作的话，目前是：  
```
轮密钥加 -> 查T-表 -> 轮密钥加 ...

```  
  
所以假设明文的每一字节是  
，密钥的每一个字节是  
，第一轮输入的每个字节是  
的话，就有  
  
  
假设我想要  
和  
产生碰撞，只需要  
  
  
即可。  
  
举个栗子，目前在T-表中有  
  
：  
  
：  
  
如果我想要判断这两次查表是否产生碰撞，只需判断他的输入是否相等，即  
  
  
由于我知道每一组明文，所以  
和  
已知，那么假设我也知道  
和  
，那么就可以根据以上关系把那一堆明文分成两组：在第一轮的  
生成中  
有产生碰撞的和没产生碰撞的。  
  
现在题目给了密钥的前6字节，所以我可以知道  
，那么接下来就是一个统计学的问题，即我可以枚举  
，每个  
都用以上规则把明文分成碰撞组和无碰撞组，然后检测碰撞组的加密速度是否明显大于无碰撞组的加密速度，如果是，就说明找到（可能）正确的  
。  
  
来个代码测试一下，这里我在分组后统计每一组时间的均值，然后检测它们的差是否大于一个阈值（THRESHOLD），如是则认为这个是一个可能正确的  
，参考代码：  
```

THRESHOLD = 10

with open('./test.txt', 'r') as f:
    raw_data = f.read()

data = []
for d in raw_data.split('\n')[:-1]:
    tmp = d.split(',')
    tmp[0] = bytes.fromhex(tmp[0])
    tmp[1] = int(tmp[1])
    data += [tmp]

key = bytes.fromhex('97ca6080f575')

def mean(l):
    assert isinstance(l, list)
    return sum(l) / len(l)

def check(i, j, ki, kj):
    col = []
    ncol = []

    for di in range(len(data)):
        p, t = data[di]
        if p[i] ^ ki == p[j] ^ kj:
            col += [t]
        else:
            ncol += [t]
    r = mean(ncol) - mean(col)
    if r < THRESHOLD:
        return None
    return r

def test(i, j):
    ki = key[i]
    for kj in range(256):
        r = check(i, j, ki, kj)
        if r:
            print((i, j), hex(kj), r)

if __name__ == '__main__':
    test(4, 8)

'''(4, 8) 0xe4 24.571021646042936(4, 8) 0xe5 20.58349909921526(4, 8) 0xe6 23.138921452926297(4, 8) 0xe7 24.225824547616867'''

```  
  
得出了  
的4个可能值。  
  
理论上接下来我只需要猜这4个值的其中一个，然后用同样的方法就可以得到  
的可能值，但实际上这4个值测试完都不能得到一个均值差大于阈值的结果。同样地，在  
表中也不能用  
推出  
。  
  
在进一步测试前先说一个结论，由于  
是可交换的，所以以上算法也是可交换的，即如果可以用  
推出  
，那么也可以用  
推出  
，可以自行用test(0, 4)和test(4, 0)测试一波。  
  
然后在进一步测试中发现，用  
可以推出  
，接着还可以推出  
、  
、  
和  
共用一个缓存位置，最后测试剩余的数据发现题目的缓存使用情况是（同一行表示共用一个缓存位置，从左到右表示缓存的顺序）：  
```
 0 ->  4 ->  8 ;
12 ->  5 ->  9 -> 13 ;
 1 -> 10 -> 14 ->  2 ;
 6 -> 15 ->  3 ->  7 ;
11 ;

```  
  
PS：另外参考了其他人的复现结果发现，即使自己生成的数据也会有这种缓存关系，原理未明，盲猜跟程序中T-表的内存位置和缓存的索引机制有关。  
  
从题目的已知信息可知  
，由于同一个缓存中相邻的两个数据可以相互推出，所以根据已知推出未知的原则，就可以构造以下攻击链：  
```
 4 ->  8 ;
 5 -> 12 ;
 5 ->  9 -> 13 ;
 1 -> 10 ;
 2 -> 14 ;
 3 ->  7 ;
 3 -> 15 ->  6 ;

```  
  
在测试中，每个未知的密钥字节都会推出4种可能，所以这里需要枚举  
种情况。  
  
PS：这些4种可能都是高6位比特相同，原理未明。  
  
然后剩下单独的  
需要枚举它的  
种可能性，合起来总的枚举复杂度就是  
，实测全部枚举大概需要半个小时。  
## 参考Exp  
```
THRESHOLD = 10

with open('./test.txt', 'r') as f:
    raw_data = f.read()

data = []
for d in raw_data.split('\n')[:-1]:
    tmp = d.split(',')
    tmp[0] = bytes.fromhex(tmp[0])
    tmp[1] = int(tmp[1])
    data += [tmp]

key = bytes.fromhex('97ca6080f575')

key = [set([ki]) for ki in key] + [set() for _ in range(16 - len(key))]
print(key)

def mean(l):
    assert isinstance(l, list)
    return sum(l) / len(l)

def check(i, j, ki, kj):
    col = []
    ncol = []

    for di in range(len(data)):
        p, t = data[di]
        if p[i] ^ ki == p[j] ^ kj:
            col += [t]
        else:
            ncol += [t]
    r = mean(ncol) - mean(col)
    if r < THRESHOLD:
        return None
    return r

def hack(chains):
    for chi in chains:
        print(chi)
        i, j = chi
        for ki in list(key[i]):
            for kj in range(256):
                r = check(i, j, ki, kj)
                if r:
                    print((i, j), hex(kj), r)
                    if j > 5:
                        key[j].add(kj)
        print(key)
        print()

chains = [
    (0, 4), (4, 8),
    (5, 9), (9, 13), (5, 12),
    (1, 10), (2, 14), (10, 14),
    (3, 7), (3, 15), (15, 6)
]

#hack(chains)
key = [{151}, {202}, {96}, {128}, {245}, {117}, {228, 229, 230, 231}, {68, 69, 70, 71}, {228, 229, 230, 231}, {84, 85, 86, 87}, {244, 245, 246, 247}, set(), {188, 189, 190, 191}, {20, 21, 22, 23}, {104, 105, 106, 107}, {92, 93, 94, 95}]
print(key)
print()


import itertools
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from tqdm import tqdm
from math import prod

c = bytes.fromhex('7972c157dad7b858596ecdb798877cc4ed4b03d6822295954e69b7ecebb704af08c054a03a374f8bdaa18ff16ba09be2b6b25f1ef73ef80111646de84cd3af2514501e056889e95c680f7d199b6531e9dd6ee599aeb23835327e6e853a9a40a9f405bd1443e014363ea46631582b97c3d3f83f4e1101da2557f9b03808a61968')
key = [list(ki) if ki else list(range(256)) for ki in key]
print(key)
print()

for k16 in tqdm(itertools.product(*key), total=prod([len(ki) for ki in key])):
    k = bytes(k16)
    aes = AES.new(k, AES.MODE_ECB)
    p = aes.decrypt(c)
    try:
        p = unpad(p, 16)
    except:
        continue
    if b'flag' in p:
        print(k.hex())
        print(p)
        print()

''' 66%|████████████████████████████▏              | 43992636/67108864 [18:25<09:26, 40781.32it/s]97ca6080f575e646e557f755bf15685eb'flag{uniform54349juliet:GL2aGs7ys8ygcW0kFBPLbwEdjLbwNltiPdX_ANqtOFbUpEh_ciY8tWZd4y2VblkUhOl-PxXJdJYK86pIHmmwcw0}''''


```  
  
  
  
