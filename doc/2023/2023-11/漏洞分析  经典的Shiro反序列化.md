#  漏洞分析 | 经典的Shiro反序列化   
 渗透安全团队   2023-11-27 22:53  
  
0x01、前言  
  
  
相信大家总是面试会问到java反序列化，或者会问到标志性的漏洞，比如shiro反序列化，或者weblogic反序列化漏洞。  
  
那我就这篇文章为大家讲解一下，不懂的哥哥直接背一下，理解一下就好了。  
  
至于为什么要选择shiro反序列化呢，不讲weblogic呢？  
  
因为我上次有幸参与金鸡电影节的临时安全负责人，具体我就不细说了。当时是内部涉及到shiro反序列化漏洞。  
  
准确的来说是Shiro<1.2.4-RememberMe反序列化漏洞。  
  
而它也被称为Shiro 550反序列化漏洞。  
  
细品细品...  
# 0x02、环境搭建  
  
  
下载地址：https://codeload.github.com/apache/shiro/zip/shiro-root-1.2.4  
  
环境：Tomcat 8.5.27 + idea 2020.2 + jdk 1.8 +maven 3.6  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfxZkfflFBNCNzwJUHL1XrInCfbhibrFcBibChFAC3yKKf5TSTvcWxhVDA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
下载之后之后直接打开，并open这个web文件夹即可，其他自行百度就行，其中还需要导入一些jstl的jar等等  
# 0x03、漏洞原理  
  
  
shiro默认使用了CookieRememberMeManager  
，其处理cookie的流程是：  
```
得到rememberMe的cookie值 --> Base64解码 --> AES解密 --> 反序列化

```  
  
然而AES的密钥是硬编码的，就导致了攻击者可以构造恶意数据造成反序列化的RCE漏洞。  
  
payload 构造的顺序则就是相对的反着来：  
```
恶意命令-->序列化-->AES加密-->base64编码-->发送cookie

```  
  
在整个漏洞利用过程中，比较重要的是AES加密的密钥，该秘钥默认是默认硬编码的，所以如果没有修改默认的密钥，就自己可以生成恶意构造的cookie了。  
  
shiro特征：  
- 未登陆的情况下，请求包的cookie中没有rememberMe字段，返回包set-Cookie里也没有deleteMe字段  
  
- 登陆失败的话，不管勾选RememberMe字段没有，返回包都会有rememberMe=deleteMe字段  
  
- 不勾选RememberMe字段，登陆成功的话，返回包set-Cookie会有rememberMe=deleteMe字段。但是之后的所有请求中Cookie都不会有rememberMe字段  
  
- 勾选RememberMe字段，登陆成功的话，返回包set-Cookie会有rememberMe=deleteMe字段，还会有rememberMe字段，之后的所有请求中Cookie都会有rememberMe字段  
  
# 0x04、漏洞复现  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfFMTmqlPP3ric2iaznicRaoL6VVP5CJD8ia1LmTc8IuJlL8daZPqgajxFyQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
复现文章https://blog.csdn.net/weixin_43571641/article/details/108182722  
# 0x05、漏洞分析  
  
  
简单介绍利用：  
- 通过在cookie的rememberMe字段中插入恶意payload，  
  
- 触发shiro框架的rememberMe的反序列化功能，导致任意代码执行。  
  
- shiro 1.2.24中，提供了硬编码的AES密钥：kPH+bIxk5D2deZiIxcaaaA==  
  
- 由于开发人员未修改AES密钥而直接使用Shiro框架，导致了该问题  
  
## 5.1、加密  
  
  
那既然我们要分析，那入口点在哪呢？  
  
Shiro≤1.2.4版本默认使用CookieRememberMeManager  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfcQRsicY2PdM2ibDfSg0wEk9u0vLPic9aCQQ3SrMNdjz6gKdSicLSwxp9qA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
而我们看看这边CookieRememberMeManager  
类继承了AbstractRememberMeManager，  
我们进去看看是什么梗  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfPgNWKr4AELgQkUU2kyqfLvc4bzoXfdqoXBoAU9yYSOliaHCecYbYkng/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
我们可以看到这边这个类里面有硬编码。  
  
然后它又继承了RememberMeManager  
接口；我们继续进去看看是怎么回事  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfckvbKDy3T5yQ25SafXt3HMvXMcIfawJTxkRRj0nnN6fvOlPFsprgLQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
看名字的话可以知道这些是登陆成功，登陆失败，退出的一些service；既然如此，肯定会调用这个登陆成功的接口，然后再去实现这个接口。  
  
所以我们直接在这个接口下个断点，看看是怎么个流程；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfo4yJnt9LpaC5wOSHicaEoI9QXWlzIIVqPRS4wKbJs1dKBeKTs6fy75A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这里看到调用了isRememberMe()  
可以发现这个就是一个判断用户是否选择了RememberMe  
选项。而我们是勾选了的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfz5qFbyvz6EgPQg8C5MdP6Fic0vLibiaZybosw7NQV8RjEmhRibJkgcIiauA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
所以我们我们条件满足，这边判断返回True，我们则进入this.rememberIdentity(subject, token, info);  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfk0omVtP0IfNPadpSXp3M7xC6icVHCmtVT1OIxUicbGruqalwtoLct2lQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
subject  
存储的一些登陆信息如session等等，而authcInfo  
存储的则是用户名；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYf0CcKU0yPJujchiaxAUfbmo9YWiaibpdBAdlb7xao0El6WFhicrr7pRlftA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
而PrincipalCollection是一个身份集合，因为我们可以在Shiro中同时配置多个Realm，所以呢身份信息可能就有多个；因此其提供了PrincipalCollection用于聚合这些身份信息，具体我们不细讲，不深入去懂原理。  
  
然后我们再F7继续跟进  
this.rememberIdentity(subject, principals);  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfUpnVDM7bFTyMOmm3GHZt1kMYDTgct2bEQ50SthATeFV7AqRt34ajjQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这我们有点懵，将身份信息干嘛？  
  
我们进入该convertPrincipalsToBytes()  
方法查看；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfworwibCBuk4M5IH4Xj4iaeJgB8sGQTSjDnJZicE9FKwvNTOPpCfa3lcQg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
看到了serialize()  
方法，难道这边开始是进行序列化了还是啥？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfoRWFNWChV7kAiaibYY3zbHkbmHKEtHBShEwDnqE7FsqgMQ9WWgIVl04A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfiadmL3Okibmjyibw6Zic3iavicT0ot6HElDoscrmWHQX6mDuo4hc8JX4qg9w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfVibiaic8hlSHO8ibYO93plEVr5xAOJlnDiaib4YF33bRnJyI4uARSIsvB4GA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
通过此处我们可以知道是跳了两层，到DefaultSerializer  
类的serialize  
方法；  
  
看到这里就懂了，这里先转为byte，写入缓冲区；  
  
然后进行了一个序列化，最后通过toByteArray()  
方法返回序列化后的Byte数组。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfUNvKHR3CxvGPxKno07GF32x4RQmv6IBSB3VwYgw6f5mQTRXjvUXG0A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后返回到原来的地方convertPrincipalsToBytes()  
内，接下来if判断getCipherService()  
方法不为空，则进入条件里面里面。  
  
我们f7进去内部看看；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfrbSibCic2Wgao8iaVLMof0WCqRs23wvYFzA2rhV2k4N41pWfNJekX4h4g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
发现又是一个cipherService，  
这是什么；我们翻译一下，因为大部分开发都会用简称；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfp6OEFXjrxIPoJaXcmmhrSGqnz8kn6QicsYBITctTrFz18CNAtvnfPsA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
也就是获取密码服务？？什么密码服务？我们再继续F7跟进发现直接推出了。  
  
那我们就 Ctrl+左键   
继续进去看。可以，发现是new了一个aes加密服务。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfZDHvn9O4uPvgD4KxkolWvQxLIS2JMvPx11OeiabvzbuLxiaRnJ0ILM5A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
那我们点击debugger处，回到刚刚那个地方；我们就不用继续进入了，我们就思考一下，这边是要获取到加密服务，如果没获取到，则不进入。  
  
获取到的话，则进入该条件；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYf2on2RVFgqbHHzTWUSXhRGzB4BHGv9DcKiahTOQBGjMbibO5dicAY56xFQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
直接F8下来，进入，然后我们再手动添加变量监视。  
  
可以发现正如我们所想的，获取aes加密服务；  
  
然后调用encrypt()  
方法，而懂点英文的，都知道这个单词是加密的意思。  
  
那我们初步判断这是个加密方法。  
  
我们f7跟进去看看什么情况。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfa3125kIDUniayoFmVicDOF8icybkeUC72fibAqJefUaDNicjdnNKkpDTZ5g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
我们可以知道这个参数是byte[] serialized，  
也就是说，此处加密我们刚刚的序列化流的数据。  
  
然后这边this.getCipherService()  
我们刚刚手动添加变量查看了，这边是获取到了aes加密服务；然后判断不问空，那肯定不为空啊，刚刚上面分析过了。然后我们进入条件判断股内部。  
```
ByteSource byteSource = cipherService.encrypt(serialized, this.getEncryptionCipherKey());

```  
  
这里调用cipherService.encrypt()  
方法并且传入序列化数据，和getEncryptionCipherKey  
方法。  
  
加密过程，我们就应该不怎么感兴趣了；有兴趣的可以自己研究  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYflpj9Imt2la6FUsocGkaz3vXt9LLAVc0Q4eu5q5iamricHP1c5TnnxOSw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
我们通过getEncryptionCipherKey()  
名字可以知道是获取key的一个方法。  
  
那我们f7进入看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfV1lPwH5HeiaE4iaB6b4N2ZtBkg0rnicgl6dYwmZUDbc0mRXic07vPywvRA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
哦豁，那我们再进一层看一下；发现直接就返回了，emmmmm….怎么跟别人不一样。  
  
那我们就不追了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfZvd3avcUKTRRwjuWQXibZN14qlic3foiaPz9uFtzofnpGR3EibTChYswOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
第一步有说到，硬编码存储在这个地方，而构造方法就在这下面，可以看到这边设置了key。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYf8fnKoI1cfqcgAEfXGhdX4oXxIBc7j5gPq5AiaBGM2VA4r1Ieg6rQdMw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
我们继续回到原来的地方，知道这边是获取加密的key就ok了。  
  
然后这边使用平台的默认字符集将字符串编码为 byte 序列，并将结果存储到一个新的 byte 数组中。那我们加密部分就结束了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfBOvApDPN8KfQTZBicyuuj58kRPxCcnZhKTm65xAThlKIOsF7jh3A1jQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 5.2、解密  
  
  
由于此处，我找不到，回溯不到，那咋办，烦恼；最后想到了我们加密的入口~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfYNzIyEHZRpUW2o4XFJ4Rk8DibXibCr0VdUicMYHE0s9CaHFuHvgTZabxw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfwXXkdLpqa1LwIfTyD2AbiabJmer4gTe6ibK4Ol42zcZrPm1TnnveTgMQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYf036fR6cOoOqlm2c6HxGS6TOktS8Kl6JFkFUYvYZBoeC1Ys6AZXgvVQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
既然自动跳到了这里，那么我们就直接在此处下个断点，重新开始  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfLianwXTnHtfJtsRLGZchM3fcoK0eRJeUsdn4uibicOicr1Y4a8hCyevMaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
随后我们进入这个getRememberedSerializedIdentity()  
方法，看看是什么东西。  
  
此处我们依然还很懵，没事；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfXFFT7nqlNksNYC8bc9sFibJS2zMibhDNMGia8TjCxhPwwrrY76qysFjuA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
一直f8，期间倒是没有什么有意思或者重点的地方；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfGwbWWOoK5d17zkpfn2M4XH2mBicBcvXxxog24ljQgm9NtXXrBQoVKYQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
直到我们走到这里，这个有一个this.getCookie().readValue(request, response)，  
这  
是要读取cookice中的数据了，这必须跟入了;  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfr4ImjEdXANw8LzwvzDjrdX7ibyteZcxnaFQronYazDmhb088dDt3PEw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这里给进到了这个readvalue()  
方法中了，我们先看看什么情况。  
  
根据名字可以知道是读取值的一个方法。读取什么值？请求包的值。  
  
通过getName()  
方法得到了key为remeberMe。然后把value置空，再通过getCookie获  
取到cookie。  
  
最后判断cookie不为空，则进入内部；  
  
随后获取到cookie的值；值则为序列化内容。然后再 return回序列化内容；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfiaN9HtQ0SFNbOyR8qlEk65F15Vfy6vunCF66XNsDAqW8hmSuXGswF2Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
随后返回到上一处地方现在remeberMe  
的值不是delete  
；而是序列化内容，所以进入到第二个条件分支。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfDPPFmFKuxo7r29PseCdwJiarW3SL0SFgI4YZoZkZ3erYY6zBBI3ovtQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
一直到这一步，进行base64解码，成为二进制数据，给了decoded的byte数组；  
```
得到rememberMe的cookie值 --> Base64解码 --> AES解密 --> 反序列化

```  
  
目前只进行了Base64解码，那还需要aes解码。我们继续跟进  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfvflbvJDhs0YuQUmMRy9tLATTjF88noDFXryOuRS7qQw2DpBHEct9dA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
返回到了上层，此处我们知道bytes是二进制数据，我们看看条件判断。当bytes数组不为空且长度大于0时，进入里面。那我们肯定满足，所以我们两步f8加一步F7进入到 convertBytesToPrincipals  
看看是什么  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfOiadPObxAw5HrUk1nWK5Wq2lB7N1EibtHDq3VBIFbBRwjY7ZuEgLqjfA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
可以看出我们接下来的步骤要依依实现了。判断key不为空，然后进入内部  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYf71Kn6EBuDChl7Jwy7P1UwcIoPtNm8rpTLQEpGQwh5iaiaLUfo5jFeC8Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfQJsvElicOO4CKELv1APNayx0fkAvrBRfbbmC8vRKLia42PWmavXocCXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
而从这里开始，就是进行aes解密的步骤了，我们F7跟进方法查看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfte2Lvy2oMLqTTtuV2wunp84thvPibAWjyKoiam2QVJSbpS5ibYBHia2Ljg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这里重新把恶意的bytes数组重新赋值给serialized，  
然后再获取加密服务：AES/CBC/PKCS5Padding  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfqyf3sd1ENXpkJicLU9jJtc8fJqpZD2lFmHTSNuYicpxpyadX4WYciazWw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
同时到达了下一步；真真正正的开始解密了，其中两个参数，第一个是加密的bytes数组，第二个是获取到key，也就是硬编码；我们 就直接进入decrypt()方法中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfZgOGobuzX8GbjzC3lwh5GwSzzJibGtanXMXOouwOuGgmqpQkLTsVy3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
解密过程的话，我不擅长密码学，这种看着我头晕，涉及到aes啥的加密解密我就会跳过。所以依旧一样，跳！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfUdUqozBAxkVkt0xibPVOwicE1uabQWZC84icvvM5Zpa5uiaRVgCcViaGbjQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
此处继续返回到了上一层，我们可以看出这个byteSource是aes解密出来的序列化流，然后再默认字符集将字符串编码为 byte 序列，并将结果存储到一个新的 byte 数组serialized  
中，那接下来我们就差反序列化了  
```
得到rememberMe的cookie值 --> Base64解码 --> AES解密 --> 反序列化

```  
  
我们继续return，返回到上一层  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfHsOqa0ywCUeg66XZiaF1boXaibp38fDkJ9jq0EM8hhPmIM03fAzaqWwg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
顾名思义，一看名字就知道是反序列化的方法，我们跟进deserialize()  
方法查看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfn5iatVcpA3TAgqyn2KLTwpvJNqsJrIjGLkosWYuTlOyejZehsMonkLQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
看到还有一层，我们继续F7跟进  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BwqHlJ29vcrkoauCN4Y5BgWd8TuDmvYfNEEoTicUq2tVic38kjEiaibp2EDkNXQNVH2310xt9M1icGRgWe68FvvKnuA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
形成反序列化漏洞的话，没有readObject()  
怎么可能呢？  
  
所以我们看到了最后一道光，就这么愉快的结束了。  
# 0x06、总结  
  
其实这个还是得学习学习加密解密的方法，才能进行编写poc，但是此处只是了解个思路。具体可参考其他文章；  
  
https://www.anquanke.com/post/id/225442#h2-7  
  
https://mp.weixin.qq.com/s/ayZKDVnN7zEbKjo5w8uqxQ  
  
  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8CKksEIzZyEb3tEFGzGYSXfribrG4jKOkRKGKYb7zk7MTNZPT6Wp3bLd2BPhuFHddIL6sqrg1d2qHQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8D0bS8ibc3XhFcDYkVusFvc3c6onthQpPGZn4v32rpOp7CeFiamGdeC7JBk0mGVsiciazLp3z0SIJAtnQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  

								[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489372&idx=1&sn=5e14ba5fa59059fb1ee405e56ef90d40&chksm=c175eaf3f60263e5ef5415a8a9fc134f0890fdb9c25ab956116d17109baf98b3bd6bed572a2d&scene=21#wechat_redirect)  

			                  
  
  
**关 注 有 礼**  
  
  
  
关注下方公众号回复“  
666  
”可以领取一套领取黑客成长秘籍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
 还在等什么？赶紧点击下方名片关注学习吧！![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**推荐阅读**  
  
  
  
[干货｜史上最全一句话木马](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489259&idx=1&sn=b268701409ad4e8785cd5ebc23176fc8&chksm=c175eb44f60262527120100bd353b3316948928bd7f44cf9b6a49f89d5ffafad88c6f1522226&scene=21#wechat_redirect)  
  
  
  
[干货 | CS绕过vultr特征检测修改算法](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247486980&idx=1&sn=6d65ae57f03bd32fddb37d7055e5ac8e&chksm=c175f3abf6027abdad06009b2fe964e79f2ca60701ae806b451c18845c656c12b9948670dcbc&scene=21#wechat_redirect)  
  
  
  
[实战 | 用中国人写的红队服务器搞一次内网穿透练习](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488628&idx=1&sn=ff2c617cccc00fe262ed9610c790fe0e&chksm=c175e9dbf60260cd0e67439304c822d28d510f1e332867e78a07d631ab27143309d14e27e53f&scene=21#wechat_redirect)  
  
  
  
[实战 | 渗透某培训平台经历](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488613&idx=1&sn=12884f3d196ac4f5c262a587590d516d&chksm=c175e9caf60260dcc0d5d81a560025d548c61fda975d02237d344fd79adc77ac592e7e562939&scene=21#wechat_redirect)  
  
  
  
[实战 | 一次曲折的钓鱼溯源反制](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489278&idx=1&sn=5347fdbf7bbeb3fd37865e191163763f&chksm=c175eb51f602624777fb84e7928bb4fa45c30f35e27f3d66fc563ed97fa3c16ff06d172b868c&scene=21#wechat_redirect)  
  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
  
