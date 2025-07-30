> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5ODUxMzg0Ng==&mid=2247500394&idx=1&sn=fa2fc8a9b7314e92c8443b15116c277e

#  G.O.S.S.I.P 阅读推荐 2025-07-10 完蛋，AI已经可以找到内核的0day漏洞啦？  
原创 G.O.S.S.I.P  安全研究GoSSIP   2025-07-10 13:10  
  
前段时间，大家可能被一则《OpenAI o3从1.2万行代码中挖出Linux内核零日漏洞》的新闻刷屏了，或者说，至少被现任OpenAI总裁Greg Brockman（嗯，他是在上次OpenAI宫斗风波里面站在Sam Altman那边的人）的转发给刷屏了：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21HQ9X6TOiciaJqrZD0G1IaA7faibZqr0wPkykgoDPiarT3cSNErobVoXHiciaRVq0NHicLzl7qPLIMDiapb4A/640?wx_fmt=png&from=appmsg "")  
  
反正，从各家媒体（当然主要是网络媒体特别是自媒体）的文章里面，我们看到**AI一次又一次被赞颂为“神乎其技”**  
（有点夸张，但是很多自媒体的报道似乎就是这样），这些文章也迫不及待要给安全研究工程师敲响丧钟。于是，带着疑问，我们去阅读了引发这些新闻报道的原文 —— How I used o3 to find CVE-2025-37899, a remote zeroday vulnerability in the Linux kernel’s SMB implementation  
，想要搞清楚究竟这个事情的来龙去脉。  
> https://sean.heelan.io/2025/05/22/how-i-used-o3-to-find-cve-2025-37899-a-remote-zeroday-vulnerability-in-the-linux-kernels-smb-implementation/  
  
  
首先介绍一下How I used o3 to find CVE-2025-37899  
这篇文章的作者Sean Heelan，他从2008年开始就关注Automatic Exploit Generation（AEG），并把自己的硕士论文研究主题定为这个方向；到了2016年他又去牛津读博，还是研究AEG相关内容；其间他在Immunity Inc做过研究员，后来还开了一家公司做了产品然后卖掉，然后2023年开始就专注于独立的安全研究。  
  
了解了Sean Heelan的背景，我们再来看看他的博客文章，这篇文章起初并不是对AI的赞美，只是作者拿他自己此前发现的一个CVE-2025-37778（针对
```
ksmbd
```

  
，一个在内核中实现SMB3协议的模块/服务，参见 https://github.com/namjaejeon/ksmbd 相关代码）来测试AI，看AI是否能很好理解。实际上CVE-2025-37778这个UAF漏洞确实不是那么看出来，注意看下图，这个
```
ksmbd_free_user
```

  
是一个自定义的内存释放函数，而实际上在图中我们并没有看到相关的代码使用了（被释放的）
```
sess-user
```

  
，因此不太容易一下子判断出来，这里很显然要做一系列的数据流分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21HQ9X6TOiciaJqrZD0G1IaA7fYV1lRe605qdgVbQlwn304eOaDUdictcpfRKlwq87C7ohibwEQSA8Xecg/640?wx_fmt=png&from=appmsg "")  
  
本来作者是想拿这个CVE-2025-37778来做一个benchmark，测试一下现有大模型对漏洞的检测能力，作者自己估计了一下，如果要理解这个CVE，人类需要分析大约3300行左右的代码（从
```
session setup
```

  
 这个 command handler 开始，追踪代码，遇到函数调用最多深入进去3层），那么把这部分代码交给LLM，让它去分析会怎么样？  
  
这部分代码大约有27000个token，作者不知道出于什么原因（太有钱了？）把这些代码和相关的prompt交给了OpenAI o3去分析了**一百遍**  
！！！这一百次分析里面，o3有66次报告说代码没有任何漏洞，有28次（错误地）报告了一些不相关的漏洞，而有8次报告了CVE-2025-37778这个问题。作者还用了其他的模型进行了测试， Claude Sonnet 3.7 在100次测试里面有3次找到了问题（不知道其他情况下是误报或漏洞，作者没说），而Claude Sonnet 3.5就一次都找不到。相关的测试结果可以在下面的链接中看到：  
> https://github.com/SeanHeelan/o3_finds_cve-2025-37899/blob/master/o3_finds_CVE-2025-37778.txt  
https://github.com/SeanHeelan/o3_finds_cve-2025-37899/blob/master/claude_3_7_finds_CVE-2025-37778.txt  
  
  
在做完这个实验后，作者可能真的是太有钱了，决定用o3来把其他command handler代码（全部都在 smb2pdu.c这个文件中）都检查100遍——总共要处理12000行左右的代码，差不多是10万token……  
  
这个特别烧钱的实验还确实找到了一个漏洞（虽然是在100次测试中只有一次报告发现了），漏洞如下图所示，仍然是一个竞态相关的double free漏洞（其他地方可能已经free了这个
```
sess-user
```

  
，而18行这个
```
ksmbd_free_user
```

  
不知道，又执行了一次free操作）。这里实际上AI工具的能力不仅体现在报告了这个问题，它还解释了相关的原因，当然LLM的分析报告还蛮长的，考虑到如果你要看100个这样的报告，怎么找到哪个是对的报告还是有点挑战的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21HQ9X6TOiciaJqrZD0G1IaA7fL9tQicP99BAWTxEekdHdIhLAlL56MkTGHD7Y2fvJwl0MkH8jibvl7iblg/640?wx_fmt=png&from=appmsg "")  
  
总之，就是这么个操作，让OpenAI的总裁都跑出来叫好，我们却觉得这是不是**鼓励大家去充值烧token的广告啊**  
？？而且关于这个报道的后续，可能大家就不太关心了，但是出于八卦之心（要不然怎么叫G.O.S.S.I.P），我们去
```
ksmbd
```

  
的GitHub repo上面围观了一下，发现除了这篇文章里面涉及到的几个问题，Sean Heelan还发现了好几个其他的问题（如下图），但是他也没说这些问题的发现和AI的关系是什么，可能更多是他人工分析的能力更强？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21HQ9X6TOiciaJqrZD0G1IaA7fsvQibQBSDeSGlNVGImCbo0Eeib2Oxf7G61n3sfF2ZybWxfZpyzU5mjag/640?wx_fmt=png&from=appmsg "")  
  
这个故事到这里，远远没有结束。G.O.S.S.I.P表示，这种**安全分析专家+强有力人工智能的组合，竟然连一些非常简单的问题都发现不了**  
，不信的话，请大家使用我们的Goshawk工具（安利了无数次！）去对
```
ksmbd
```

  
进行分析，看看是否能够找到问题？  
  
G.O.S.S.I.P 成员在7月初花了2天时间，使用Goshawk结合人工分析，**很快就在大模型分析了100遍的代码（对，就是ksmbd/smb2pdu.c文件）中确认了两个新的内存破坏bug**  
，来看看下图，在这里（
```
ksmbd/smb2pdu.c
```

  
文件的
```
smb20_oplock_break_ack
```

  
函数中）我们发现的Use-After-Free问题，完全依赖于Goshawk对
```
opinfo_put
```

  
这个自定义内存管理函数的识别。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21HQ9X6TOiciaJqrZD0G1IaA7fahldy5iaIeoic07vNj4xl2eNrurmopQLIu3nUQFicKVfs0JbsSWObrpdg/640?wx_fmt=png&from=appmsg "")  
  
更重要的是，这个错误模式在代码中反复出现（感觉就是开发者不断重复犯错），除了上面提到的
```
smb20_oplock_break_ack
```

  
函数，在另一个
```
smb21_lease_break_ack
```

  
函数中也出现了类似的错误：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21HQ9X6TOiciaJqrZD0G1IaA7f7qRATFThFbttoGlVI0gJK1sJMoqK6Rict9WbnYibsUFdP9z8xjOA8Kyg/640?wx_fmt=png&from=appmsg "")  
  
我们很快向
```
ksmbd
```

  
项目的主要维护者Namjae Jeon提供了相关的bug报告及修复建议，他也很快认可了我们的分析，并（周末加班）及时修复了问题（https://github.com/namjaejeon/ksmbd/commit/0329cf14f6f48ca3f4ae6235571f06cb0a06b106 已经提供了patch），给Namjae Jeon点赞！  
  
回过头来，我们想要给这些所谓的“AI漏洞检测”泼一点冷水，**虽然目前确实能够看到AI在协助人类分析安全漏洞上面有一点贡献，但是这种动辄大量使用算力去反复检测，最后却依赖人工去从一大堆错误结果里面挑选出正确结果的做法，和以前的使用静态分析工具分析漏洞比起来，有什么优势呢？大家都是很多误报，但静态分析工具起码不会让全球变暖加剧**  
，对吧？我们还是更坚持静态分析为主、人工智能为辅的漏洞检测策略，也许未来确实会有那么一天AI能够完全实现高效准确的漏洞检测，但高水平安全分析人员的含金量，现在依然很足~  
  
  
