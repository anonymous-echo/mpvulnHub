#  蓝队研判技巧（一）-- 基础篇&WireShark篇   
 进击的HACK   2024-11-23 23:55  
  
> fkalis早期在i春秋的投稿文章  
> 原文链接：https://bbs.ichunqiu.com/thread-63452-1-1.html  
  
> **看了很多关于护网的文章，大多文章都只有关于面试题的文章，并没有真正的蓝队实战的一些分析，关于对可以流量如何进行研判的分析，因为我也是第一次参加关于红蓝对抗的蓝队项目，我想将我在红蓝对抗中学习到的实战的东西交给大家，以下都是我的拙见，有什么不足请师傅们提出，我将尽力改正和学习。**  
  
## 1. 对客户的企业架构要有一定的理解  
#### （1）为什么这里要将企业的架构放在研判的第一位  
```
因为在很多情况，我们对流量的研判
是需要根据真实的企业架构来进行的，
只有熟悉的企业的架构才能对流量的
研判有个确定的结构。
```  
  
例如：为什么一台外网的天眼会接受到一个内网对另一个内网的攻击报警呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kBjLYDdg9mZVCwibwh7Kaic3FOtJsb4ibXicKQcIuPicVoGLggWibAic8vNqxw/640?wx_fmt=png&from=appmsg "")  
  
这时候我们可能就会有很多疑问？  
```
1.难道红队已经在内网进行横向了吗，但是我们的设备是外网监测设备啊
2.难道红队已经控制了一台内网设备了吗，为啥之前都没有动静
3.红队到底是从哪里进行攻击的，应该在哪就行漏洞修复呢？
  ....
```  
  
这就是不知道架构的困难之处，如果不知道企业的架构，就相当于一个盲人一样，无法确定攻击的线路，无法解决各种疑问。那如果我们知道架构会是怎么样的呢？  
  
在这里的企业架构，实际上这里的攻击来源ip是企业的一个负载均衡  
  
当外界访问该企业的网站的时候，实际上是通过负载均衡然后到达内网的一台设备，从而实现web的访问的，由于天眼架设的位置在负载均衡之后，所以天眼获取到的流量是经过负载均衡后的流量，这时候就会导致访问的ip变为内网的负载均衡的ip，所以导致一个内网访问一个内网的效果，所以我们只有只有知道了这个企业的架构才能具体的情况进行具体的分析  
#### 可能文字比较难懂，我将这个流程整理成一个图片方便大家理解  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kXKMU9LJWYAYpuIu1SPoPMSHa3VK30hNibYhUPVCaGuf24FITEO51p2Q/640?wx_fmt=png&from=appmsg "")  
#### （2）那么我们在企业的架构中最重点需要关注什么内容呢。  
```
1.企业的对外访问服务的ip
2.企业的负载均衡的ip
3.企业的vpn
4.企业的不同网段
5.设备探针的所在位置
    ....
```  
## 2. 熟悉设备的原理  
> 任何设备都不是万能的，不要把设备想象的过于智能，他实际上会有很多误报，要想冷静的对这些误报进行分析研判就需要使用者对设备的原理进行了解，从而分析该误报产生的原因，进行更好的研判分析（这里以天眼为例）  
  
  
####   
#### 例如：对天眼来说，他的部分规则会来自qax的威胁情报中心，当qax威胁情报中心标记的域名为恶意域名的时候，就会在天眼分析平台出现一个ioc，也就是规则，当用户的内网有对外解析该域名的请求时候，就会直接报警，无论DNS解析是否成功，他都会报警失陷。这就会导致一些误报  
  
#### 例如：这里报警报了远控木马失陷，看到是不是很慌  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kNt7gbj3Q8HMt7jvlq6NNIIOslf6ibZWsUh7UYpxCvhL0XiaEBs5rzp8Q/640?wx_fmt=png&from=appmsg "")  
#### 但是这里实际上就是我说的当用户的内网有对外解析该域名的请求时候，就会直接报警，无论DNS解析是否成功，他都会报警失陷，我们可以查看他的流量情况  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1k8Eu4kpFxsNnh2p5GhPHOzpUFYRzr81ibB6TSvTnSxqVsrVC4I2w9m2w/640?wx_fmt=png&from=appmsg "")  
  
#### 会发现他只有一个域名的DNS请求解析，连DNS解析都没有成功，没有返回包，但是依然报了失陷，所以这就是设备的一些小误报  
#### 补充：  
  
为什么会去请求解析这个恶意域名的，可能是因为内网的某些设备有一些垃圾软件,这些垃圾软件有对外的DNS解析，但是被拦截了，但是因为有请求解析，所以天眼还是报警了，但是并没有成功。  
## 3.wireshark的一些使用技巧  
> 由于在面对很多流量分析的时候，并不是单单通过设备就可以进行研判的，很多都是需要通过pcap包进行分析，所以对wires hark的使用必不可少，但是wireshark对于新手来说并不是很友好，因为他复杂的过滤规则，让入门的时候不知道从哪里下手，实际上我们不需要完全掌握wires hark的过滤语法，通过下面这些技巧，也可以很好使用wireshark进行分析。  
  
  
#### （1）追踪tcp流  
  
当我们用wireshark对tcp等协议进行分析的时候，他会将一次请求的tcp拆分为多个包，这就会导致我们分析的时候有点困难，需要一个个看，这时候我们就可以使用tcp流，让这些整合成一个请求，格式和burpsuite类似，这有助于我们的分析  
####   
#### 非常复杂  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kcY8LW9Bfn8UY9w5f9G95B6Vh8ibRUVbiak75S1Wh1Ga1s5L17gCZhmAg/640?wx_fmt=png&from=appmsg "")  
####   
#### 使用tcp流将他们整合  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kw5RP4YdQvw9aS2ETibtTlwJdNFXA4RBlHdibicATDNfvM4ADm4t0t6Oiaw/640?wx_fmt=png&from=appmsg "")  
####   
#### 可以获取到完整的请求，直接对该请求进行分析  
```
红色的表示请求，蓝色的表示响应
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1k2I53ur0ssmTN61fico27DnAib3nnmJngmgicuj1lNzFmullayCR7QV6Fg/640?wx_fmt=png&from=appmsg "")  
####   
#### （2）筛选方式  
#### 众所周知，wireshark难就难在他的过滤语法，由于他的流量很多，所以就需要过滤语法，如果不是一个经常使用wireshark的人来说，这么多的语法绝对是灾难，但实际上并不需要记住语法，wires hark提供了一些功能进行直接过滤。  
####   
#### 正常的过滤语法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kjiaUaZ9GVtvbr2X8MDYFFiaicQjU8Vcdh9aNAoo2lrLiblgNCeRSusamlQ/640?wx_fmt=png&from=appmsg "")  
####   
#### 我们可以使用这种方式进行过滤  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kJF3PXgGrrwh4A8h9yKTbdWWhvleI1WKSdRYQzsIr5ESd0wr2qoxaVA/640?wx_fmt=png&from=appmsg "")  
#### 将想要过滤的东西选中，这里想要过滤的就是目的为这个IP的流量，这样设置后他就会自动补充过滤语法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kWyibI3QI9apicAWzR1ueEGTpK0gISqXN76AVxMraFD1ic5r1aVpAI5zdQ/640?wx_fmt=png&from=appmsg "")  
#### （3）提取文件  
#### 这个技巧只是偶尔会使用到，因为大部分设备都会自带文件流的提取了，但是偶尔还是会遇到的，有的CTF题目中也会遇到  
#### 1. 正常打开打开cap或者pcap文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kNibzmoqMLhPocKZv4GPrkicxV45YYHEv83YJPZaKC9k7vrJM0SF593Xw/640?wx_fmt=png&from=appmsg "")  
#### 2. 找到想要还原的zip数据包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kqCqPsoS0k4uxSSoACcTbic60oKIWDzQjiciacgEpcTy62fEk78uShRVrg/640?wx_fmt=png&from=appmsg "")  
#### 3. 点进数据包中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kJm1Fmgl2XxjDfHagib5CalDEhSpnCPCLIntrwbv1GQrjY22jNz85e1w/640?wx_fmt=png&from=appmsg "")  
#### 4. 选中media type  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kaSwBgXmicjIZuN5wozX8VFXCC67A6ic9TWxst1wnkTR3cwb7LwnEicFfw/640?wx_fmt=png&from=appmsg "")  
#### 5. 右键选中复制 ---》 Hex Stream  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kpA4mjiaEjaeQMNBtgOFxK7D2ib2YmqmAo94Uuu1dKMZTmunfZXElXx5w/640?wx_fmt=png&from=appmsg "")  
#### 6. 打开winhex 16进制查看工具  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1klz9Thwb8DicpnsnIIkNCPu3mK9JZp0MMYZN9ia93MmDwNuIU0jELwWMQ/640?wx_fmt=png&from=appmsg "")  
#### 7. 点击编辑从剪贴板粘贴  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kmET0HBqpD0NaiaHPDEsFpQNk4Pp5IdugibKgib4oHsic1ClsF3EOrKlK0A/640?wx_fmt=png&from=appmsg "")  
#### 8. 选中 ASCII HEX  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kGzQXk1iaCIkia3KJnzmrtD0xLCbKgcXUL7yWcIetibgpe63eB9837icSMg/640?wx_fmt=png&from=appmsg "")  
#### 9. 就可以得到还原的zip文件了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kfU720UBWE3unKnIib4JibVRCy4Kn85hSibzkv6evGtmusBlM8SPPm44JA/640?wx_fmt=png&from=appmsg "")  
#### 10. 另存为zip即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kabtsHuYkF0lt6ic9YOQwD4RgPhs05wFeDhMdZtAXgtuiaDBHXbWUhuibQ/640?wx_fmt=png&from=appmsg "")  
  
11. 成功打开，没有损坏  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfSpGLKiczxicEzTgyiahqos1kkiaRAZbk6D0SiaS77TafxT8sdWWln0YVrGibnriaTPfsjdcAu5Dr2GPGhg/640?wx_fmt=png&from=appmsg "")  
  
****  
**这就是蓝队研判的基础知识，下章我会对如何研判进行具体的分析，具体到某个案例，如何一步步确定他是否成功，是否是攻击等等.....**  
  
  
