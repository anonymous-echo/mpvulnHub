#  揭秘以太坊 Vanity 生成器 Profanity 私钥破解漏洞   
原创 慢雾安全团队  慢雾科技   2022-09-21 18:45  
  
By  
: Johan  
  
  
近日，Wintermute 钱包遭攻击损失约 1.6 亿美元，被盗原因是   
Wintermute 为了节省 Gas 费使用了 Profanity 来创建 Vanity 钱包（开  
头 0x0000000），此前去中心化交易所聚合器 1inch 发布了一份安全披露报告，声称通过名为 Profanity 的工具创建的某些以太坊地址存在严重漏洞。慢雾安全团队对此事件进行了深入分析，并分享给大家。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLbbibib9018OMZDoM7DVTS7QNt5XfeE3FbeRQgWS8bCkr8R5xVXO1icrwicBBjhiaRhoKo01VP2OlUrOzA/640?wx_fmt=png "")  
  
  
椭圆曲线加密（ECC  
）是区块链领域最常用的加密算法，ECC 是一个加密算法大类，它包含了多种不同的曲线和加密算法，例如 secp256k1/secp256r1/ed25519/schnorr 等，比特币和以太坊都是使用 secp256k1 加密。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLbbibib9018OMZDoM7DVTS7QNaeTTUicuTS0FKAbCp9bPCyR2AQWej9osTWpZps5FGNhuQzeyqicQYh7Q/640?wx_fmt=png "")  
  
  
  
在使用以太坊时，我们首先会生成一个私人账号（以 0x 开头 + 40 字母），具体过程如下：  
  
  
（1）生成一个不可预测的随机数种子，通常基于系统的 /dev/urandom 随机发生器；  
  
（2）利用随机种子生成一个私钥（256 位，32 字节）  
  
（3）通过私钥生成公钥（64 字节）  
  
（4）公钥使用 keccak-256 哈希算法，取哈希值十六进制字符串后 40 个字母，开头加上 0x 生成最终的以太坊地址。  
  
  
特别记一下这些公私钥的大小，因为它关乎我们后面要做的计算量。  
  
  
这里需要提的一个关键公式：  
  
  
   
Q = kG  
  
  
这是私钥推导出公钥的核心算法，私钥推出公钥计算很简单，但反向推导几乎不可能。  
  
  
Q 是公钥，k 是私钥，k 由有限域内的大整数构成，相当相当大，以致于几乎不可能去猜测，G 是椭圆曲线上的一个点，默认是一个固定的值，kG 就是 k 个 G 点相加（椭圆曲线的点相加不是简单的实数相加，计算方法这里不展开讨论）。  
  
  
如果我们想要穷举以太坊账号，找到 Vitalik 的私钥，那么在知道他的公钥后，最多需要进行 2^256 （2 的 256 次方）次的   
Q = kG  
 计算，对大数字我们天然不敏感，所以我把它换算成工作量，就是目前一台苹果 M1 电脑大概 40M/s 的速率，那么大概需要的年份是 8 后面跟上 62 个零。一万年太久，只争朝夕。  
  
  
有一些错误的私钥生成方法，会导致私钥的取值范围变成更小范围内的数值，变得可猜解。常见的原因有：  
  
  
（1）随机数种子不够随机，例如使用了时间戳做为随机数种子，那么我们只要穷举过去一段时间所有的时间戳就能找到生成公钥所用的种子和私钥；  
  
（2）软件算法存在缺陷，导致随机强度不够（Profanity 正是存在这样的缺陷  
）；  
  
  
Profanity 的设计目的，是帮助人们生成一个具有特殊视觉效果的账号，比如以特殊字符开头或者结尾的账号，另一方面，一些开发者使用它来生成开头为很多个 0 的账号，如 0x00000000ae347930bd1e7b0f35588b92280f9e75，它可以在调用智能合约时达到节省 Gas 的效果。  
  
  
Profanity 为了更快地爆破出 Vanity Address，只在程序的开头获取了一次随机数，后续所有的私钥都是基于这个随机数迭代扩展而来，我们来看一下它的随机数生成算法：  
  
```
Dispatcher.cpp

cl_ulong4 Dispatcher::Device::createSeed() {
#ifdef PROFANITY_DEBUG
    cl_ulong4 r;
    r.s[0] = 1;
    r.s[1] = 1;
    r.s[2] = 1;
    r.s[3] = 1;
    return r;
#else
    // Randomize private keys
    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<cl_ulong> distr;
    cl_ulong4 r;
    r.s[0] = distr(eng);
    r.s[1] = distr(eng);
    r.s[2] = distr(eng);
    r.s[3] = distr(eng);
    return r;
#endif
}
```  
  
  
这里使用了   
rando  
m_device  
 来获取系统提供的随机数，这个随机数源是满足加密所需要的强度的。  
但是当我们注意到变量类型时，我们发现   
rd()  
 返回的是一个 32 位长度的随机值，上文我们提到一个私钥是 256 位长度，那么一次获取随机数的过程并不能填充整个私钥，于是 Profanity 使用   
mt19937_64  
 产生随机数来填充整个私钥。  
mt19937_64  
   
和  
   
random_device  
   
的随机算法有着本质的区别，  
mt19937_64  
   
是确定性的，它的随机性依赖于输入的随机数，并不产出新的随机性。  
  
  
也就是说，如果  
   
rd()  
   
传递给  
   
mt19937_64  
   
的值在某个范围，那么  
   
distr(eng)  
   
的值也在对应的某个范围，  
createSeed  
   
函数返回的 r 值自然也是在某一个范围。  
  
  
关键点来了：  
   
rd()  
   
的所有可能性是 2^32，离私钥的安全性（2^256）相差了 224 个数量级，但是 2^32 这个数量级也挺大的，那么它需要多少计算量才能破解出私钥？  
  
  
Profanity 在获取到第一个私钥 SeedPrivateKey 以后，为了碰撞出需要的账号地址，会通过一个固定的算法不断跌代这个私钥，最多 200 万次（数值来源于 1inch 披露的文章），这个公钥的计算方式可表示为：  
  
  
PublicKey = kG = (SeedPrivateKey + Iterator)*G  
  
  
Iterator 是一个递增的数字，当 PublicKey 已知时，我们可以通过穷举 SeedPrivateKey 和 Iterator 来得到 SeedPrivateKey，计算量大概为 2^32 乘以 200 万次，在 1 台 M1 电脑上需要 60 多年时间，看上去这辈子有希望 :D。如果我用大量算力更大的显卡进行并行计算，那么在几天甚至几个小时碰撞出想要的结果也完全可以。  
  
  
刚好最近以太坊转 PoS 共识，存在大量的闲置的显卡算力，如果矿工拿显卡来破解这个私钥，那不是分分钟就能成功？当然这个阴谋论没有意义，我们只想研究破解的可能性。我们更希望能用不那么暴力的方法来解开私钥。  
  
  
我们稍微移动一下等式两边，对上面的公式进行变换，可得：  
  
  
SeedPrivateKey*G = PublicKey - Iterator*G  
  
  
我们可以思考另一种攻击方法，如果首先预计算 SeedPrivateKey*G，需要最多 256 G 左右的内存空间去存储计算结果，在一台普通的服务器上完全可以做到，所需要的计算是 2^32 次，大概几十分钟就可以完成。然后我们再把需要破解的 PublicKey 代入等式右边，然后对 Iterator 跌代碰撞，所需要的计算量大概是 200 万次，还有 200 万次的查表，所需要的时间是秒级。这，就有意思了，原来 32 位的随机数是这么的微不足道，任何人都有可能在几十分钟内还原出私钥。  
  
  
至此，我们总结出了 Profanity 的漏洞成因，是由于未对 256 位私钥进行足够随机播种，导致私钥取值范围严重降低。同时也分析了对这类随机性问题的破解可能性，希望能给大家一些启发。  
  
  
**往期回顾**  
  
[](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247496353&idx=1&sn=f62ef577c557a59b94f05728a695831b&chksm=fdde8c26caa905308cc4e3aa574a3a24f6123ce23a206099f3a0ed8ebce4b777a70a3bbda637&scene=21#wechat_redirect)  
[慢雾解读 | 区块链分叉带来的安全挑战](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247496417&idx=1&sn=d98a78d0e4a480856a13a66056a58afc&chksm=fdde8c66caa905702bc7c5c4e1c77f270acbfa818daf3719b890dc70db2ce1281fc1345814bb&scene=21#wechat_redirect)  
  
  
[共迎中秋 | 一份讲究的慢雾定制礼品（文末有惊喜）](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247496353&idx=1&sn=f62ef577c557a59b94f05728a695831b&chksm=fdde8c26caa905308cc4e3aa574a3a24f6123ce23a206099f3a0ed8ebce4b777a70a3bbda637&scene=21#wechat_redirect)  
  
  
[暗夜小偷：Redline Stealer 木马盗币分析](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247496292&idx=1&sn=ffbcd901857403e0a3b4c384644569e0&chksm=fdde8ce3caa905f5777d57bba9a5b881bfbf20bc93931c9d087238b76ed24a5a603559ea371c&scene=21#wechat_redirect)  
  
  
[“零元购” NFT 钓鱼分析](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247496261&idx=1&sn=9c657f56128df327e27c49fc49d4cc02&chksm=fdde8cc2caa905d4a9cd709c44888b54ccf4071301056052f0bc800b6d5d487873d3bafd124a&scene=21#wechat_redirect)  
  
  
[引介｜EVM 深入探讨-Part 1](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247496252&idx=1&sn=f21662916829d32dfb36b50cec5faeff&chksm=fdde8cbbcaa905adf384a9b788ad2dea063f12029970328a3955d12012251d5fbe083454e717&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLYHFF8px39DPwMXPrReY6aFaJyD325uT5KCgM67X31H0icFpibWHDQ1PrJjqiayjkqwicxhC32VxtHGVA/640?wx_fmt=png "")  
  
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
  
