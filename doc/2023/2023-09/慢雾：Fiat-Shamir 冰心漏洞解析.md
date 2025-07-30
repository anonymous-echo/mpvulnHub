#  慢雾：Fiat-Shamir 冰心漏洞解析   
原创 慢雾安全团队  慢雾科技   2023-09-24 14:59  
  
by: Johan  
  
  
**背景**  
  
  
  
Frozen Heart “冰心”漏洞，  
由   
  
Trail of Bits 团队命名，  
其中 Frozen 代表 FoRging Of ZEro kNowledge proofs，Heart 指 Fiat-Shamir transformation 是很多 proof system 的核心。该漏洞  
指应用了“  
弱 Fiat-Shamir”变换  
，只对证明者的部分消息进行散列而不散列公开信息（比如参数、公开输入等），因此出现的安全问题。  
  
  
下面我们将对这个漏洞进行全面的解析，  
我们先来谈下什么是  
 Fiat-Shamir 变换。  
  
## Fiat-Shamir 变换  
  
  
Fiat-Shamir 变换，又叫 Fiat-Shamir Heuristic 或者 Fiat-Shamir Paradigm，是 Fiat 和 Shamir 在 1986 年提出的一个变换，用于将交互式零知识证明协议转化为非交互式零知识证明协议。  
它通过将协议中的随机挑战（challenge）替换为哈希函数的输出来实现这一转化。  
这样，证明者可以生成证明并将其发送给验证者，而无需进行交互式的挑战和响应。  
  
  
Schnorr 证明是一  
种  
交互式零知识证明协议，它允许证明者向验证者证明某个陈述为真，而不需要透露陈述的细节，同时验证者可以进行交互式的验证。  
它通常用于证明者知道某个秘密值而不透露该秘密值的情况。  
  
  
借助 Fiat-Shamir 变换，可以将 Schnorr 交互式证明改造成非交互式。  
  
  
Schnorr 可以在有限域或椭圆曲线（EC）上实现，技术规范基本相同，只是底层循环群不同。下面我们主要以有限域的形式来描述这两个过程   
[1]  
：  
  
```
```  
### 基于有限域的实现  
  
  
1. 交互式  
  
  
首先，Alice 计算 A = g^a mod p，其中私钥 a 取值 [0, q-1]，然后公开公钥 A；  
  
  
然后，Alice 在不公开 a 的情况下，向 Bob 证明他知道 A 对应的私钥 a：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZwuBRkNyjiapIvJ4l4A9wnzTEgfws1uldjM8GJ5p2GF6SEwz5iahq3mVrc0HXdDyu1nVgqWt8pI8MA/640?wx_fmt=png "")  
  
  
如果 check 为 true，那么就能证明 Alice 知道 a ，原理如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZwuBRkNyjiapIvJ4l4A9wnzf44Bo9xmkBibyuMUY2Lkc0KaGKRUPGYU1Vgia0S7gaiazjcgSoRLeXf7w/640?wx_fmt=png "")  
  
  
这里之所以需要由 Bob 生成随机 c ，是因为如果攻击者在公开 A 之前知道了这个值，那么他就可以在不知道真实 a 的情况下伪造证明。攻击者伪造 (A, V, r) 方法如下：  
  
  
1）生成一个随机值 r  
  
2）V 计算方法不变，令   
  
  
Verifier 收到这三个参数后，代入验证公式，也是可以通过验证的。但是我们注意看这些参数的生成过程，它们与要证明的秘密值 a 没有任何关系。  
  
  
2. 非交互式  
  
  
非交互式的改造也很容易，在交互式的基础上，把 Bob 随机生成 c 的过程，改成参数  
的 Hash 形式：  
  
  
  
### 基于椭圆曲线的实现  
  
  
首先，Alice 计算 A = G x [a]，其中私钥 a 取值 [0, n-1] ，然后公开公钥 A；  
  
  
接着，Alice 在不公开 a 的情况下，向 Bob 证明她知道 A 对应的私钥 a：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZwuBRkNyjiapIvJ4l4A9wnznPOsScTs85Uso5plqkHbhseTibAfE2THuP9GSicqicst6IlUzPL4Pb40w/640?wx_fmt=png "")  
  
  
如果 check 为 true，那么就能证明 Alice 知道 a ，原理如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZwuBRkNyjiapIvJ4l4A9wnz2NcFzOnZdWH0anmTwrCGHpia8LMrSicwcibT65lsQO6exDbm5I9DGcvgw/640?wx_fmt=png "")  
  
  
非交互式的实现方式与上述的基于有限域的实现方式相同，就不再赘述。  
##   
## 弱 Fiat-Shamir 变换  
  
  
上面非交互式的实现过程中，随机数：  
  
  
  
  
是一种正确且安全的生成方式，但遗憾的是，在早期的一些论文中，并没有对这个过程进行严密地描述，只是简单地描述成：  
  
  
  
  
这就存在一个安全问题，我们称它为弱 Fiat-Shamir 变换，它可以被用于伪造证明，通过预计算 A，欺骗验证者。  
  
  
使用以下方法重新构造参数 (A, r)：  
  
  
生成一个随机值  
  
计算，计算方法不变  
  
计算  
  
我们可以看到这个 A 变成了一个和 a 无关的参数，代入验证方程：  
  
  
可以等于 V 。  
  
  
也就是说**攻击者可以在不知道秘密值的情况下通过协议验证。**  
  
  
还有一些论文  
 [3]   
描述这个过程如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZwuBRkNyjiapIvJ4l4A9wnz1dw9VPPXjYy7KvZgvZA3Aokw0co68Xr7MRfD4PRRusa2R6AcpqVBgA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZwuBRkNyjiapIvJ4l4A9wnzwfVNhUpy1uibNuC4PtjibSGFzIrvU6X72XaG8k8rVWO5keu212abtpsw/640?wx_fmt=png "")  
  
  
其表达的内容是相同的。  
##   
## 冰心漏洞  
  
  
Trail of Bits 团队曾发表文章  
 [2]   
指出 Bulletproofs 和 Plonk 等 ZKP 系统中的 Fiat-Sharmir 实现存在漏洞，使得恶意用户可为随机 statement 伪造 proof。  
  
  
以 Plonk 为例，在证明生成的 Round 2,3,4,5 中，均利用了 Fiat-Shamir 算法生成随机数。  
  
  
在论文  
 [3]   
中调查了许多现代零知识证明系统的开源实现，发现有 36 个使用了弱 Fiat-Shamir 变换，包括 Bulletproofs、Plonk、Spartan 和 Wesolowski 的 VDF 等。攻击者可以生成通过验证的证明，而不需要知道有效的证明秘密。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZwuBRkNyjiapIvJ4l4A9wnzktugvs4lhoR24YYZfPjyVGyuJSib7A6jribib25IgeX4q9sAY1HcnVZfA/640?wx_fmt=png "")  
## 漏洞实例  
###   
### 1. gnark  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZwuBRkNyjiapIvJ4l4A9wnzC2f4DicTgZicp8YicAPS9rvlGSpKbNicDArsnVoibS3oDAogTon9xkickX0Q/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZwuBRkNyjiapIvJ4l4A9wnzALut78k6aK0pcf7zFkiaibWiaQUduwKNNNSyWWarJcXiaNywuSbxgKqiaPQ/640?wx_fmt=png "")  
  
  
这里 fs 就是一个 Fiat-Shamir 计算实例，在 Round2 证明计算 z(X) 参数时，由于没有将公共输入绑定到 challenge，导致了可以伪造证明信息。  
  
### 2. snarkjs  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZwuBRkNyjiapIvJ4l4A9wnzHxmsPDq1Hh3ARc9sybmpdGLiatV3lt8KYaSnbibicuiar72nlW96upausw/640?wx_fmt=png "")  
  
同样由于没有包含 publicSignals ，导致可以伪造证明信息。  
##   
## 总结  
  
  
从披露的内容我们可以看到这个漏洞的通用性和广泛性，它会对零知识证明造成严重危害，  
在实际应用中我们需要注意审查 Fiat-Shamir 实现的正确性，将公共见证数据也加入到随机数生成中，避免被攻击者伪造证明。  
  
  
最后，感谢领先的⼀站式数字资产⾃托管服务商 Safeheron 提供的专业技术建议。  
##   
## 参考文档:  
  
[1]. https://datatracker.ietf.org/doc/html/rfc8235  
  
[2]. https://blog.trailofbits.com/2022/04/13/part-1-coordinated-disclosure-of-vulnerabilities-affecting-girault-bulletproofs-and-plonk/  
  
[3]. https://eprint.iacr.org/2023/691.pdf  
  
  
**往期回顾**  
  
[慢雾：Balancer.fi BGP Hijacking 攻击分析](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247498451&idx=1&sn=4be6dd06dd4ae64fd91d663cf3310387&chksm=fdde8454caa90d425d8fcc2e773878acf5ad860c3264404e5fbb19118d226ba79b8dffa85b05&scene=21#wechat_redirect)  
  
  
[智能合约安全审计入门篇 —— Contract Size Check](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247498432&idx=1&sn=3238076ebd6e1f8e35f577c51f2cec88&chksm=fdde8447caa90d514fe716549885a7285d3c587da66f255f35896b3c02a800adefb67d3e6404&scene=21#wechat_redirect)  
  
  
[一周动态 | Web3 安全事件总损失约 4255.4 万美元](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247498418&idx=1&sn=c69b877ab0b5e32afe7cd97bb992c2f9&chksm=fdde8435caa90d239f06cdca30855e7472f952a8b04d64c21e8872435ccdbd2c7d7f812f4287&scene=21#wechat_redirect)  
  
  
[慢雾作为内容贡献者参与的《数字资产安全、合规与风险管理》白皮书已正式发布](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247498395&idx=1&sn=c2f09bfc1ed4a5511218bca27dfa2794&chksm=fdde841ccaa90d0a958f2f57e713d0a8a30819ae9b830a31bb965dfd550043a9965c13e5b00d&scene=21#wechat_redirect)  
  
  
[哈希函数的隐藏危险：长度扩展攻击与服务端验证的安全隐患](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247498380&idx=1&sn=e469b9cbc59392bcb3dbe5b3a10b505f&chksm=fdde840bcaa90d1deb25fc237623e2233d255030bfe1cf87782dc81d6c1e621f377d0fb4cf5f&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLazKt6yZQQvqiccDeUu8Togv4VUdq4r7iak19Hta2pfbzPrGohPNR71WxPKrBoK9nyibPVL7ssCuW3yA/640?wx_fmt=png "")  
  
**慢雾导航**  
  
  
**慢雾科技官网**  
  
https://www.slowmist.com/  
  
  
**慢雾区官网**  
  
https://slowmist.io/  
  
  
**慢雾 GitHub**  
  
https://github.com/slowmist  
  
  
**Telegram**  
  
https://t.me/slowmistteam  
  
  
**Twitter**  
  
https://twitter.com/@slowmist_team  
  
  
**Medium**  
  
https://medium.com/@slowmist  
  
  
**知识星球**  
  
https://t.zsxq.com/Q3zNvvF  
  
