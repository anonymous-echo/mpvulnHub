#  G.O.S.S.I.P 阅读推荐 2023-08-09 又见CPU瞬态漏洞~   
原创 G.O.S.S.I.P  安全研究GoSSIP   2023-08-09 20:41  
  
USENIX Security好像最近几年演变成了安全的“大空头”，每到会议前就会爆出来一些噱头十足的安全问题，直指大厂。今年USENIX Security也不例外，两篇论文让牙膏厂和苏妈都很头疼。让我们来看看这两篇论文。  
  
首先是针对Intel CPU的“Downfall Attacks”，这篇论文 Downfall: Exploiting Speculative Data Gathering 只有一名作者（来自UCSD），但是套路一点没有少。除了标准的论文发表，还配上了网站（现在这种描述特定攻击的网站的风格都趋同化了，真是太无聊）  
> https://www.usenix.org/system/files/usenixsecurity23-moghimi.pdf![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21H0zesURJwXtt5ic316bXZY01z6toteic1qNmoEtHv2kYBGk5XtOFeHccFr8MUvCDaUB1fcePElHlaA/640?wx_fmt=png "")  
  
  
> https://downfall.page/![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21H0zesURJwXtt5ic316bXZY07EmuGlWQJyic8WNUX0wcBZF2k51PNnlgTb3fMn29vGUD6TUfu3YdlbQ/640?wx_fmt=png "")  
  
  
  
用一句话来总结，Downfall攻击的核心漏洞（CVE-2022-40982）和Intel CPU的gather指令有关。这个指令（或者说特性）在Intel Haswell架构时期（2013年发布）就已经引入了，是AVX2指令集的特性之一。简单说来就是允许所谓的“跨距访存”，即内存访问时，每个SIMD数据的向量数据元素可以来自不相邻的内存地址。下图是gather指令的执行示意图，更多细节大家可以去参考Intel官方文档和一些网络文章。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21H0zesURJwXtt5ic316bXZY064pnibZglQQFuyLAkqGXI5NbEia0fe6qyvoplpPk0dNgDUUrG2ia7cicwA/640?wx_fmt=png "")  
  
关于Downfall攻击的技术细节，编辑部最近疲劳度太高，这次就偷懒不给大家介绍了，大家可以去关注论文（USENIX Security 2023的论文集今天已经上线了）。你可能要问，这个攻击的危害是什么？先看作者提供的三个视频：  
  
  
  
  
总之，Downfall攻击能够泄露很多信息，作者提出的Gather Data Sampling (GDS) 和 Gather Value Injection (GVI) 能够绕过普通的进程间数据隔离，还能突破 Software Guard eXtensions (SGX) 的数据防护。如果你想复现，也可以访问代码：  
> https://github.com/flowyroll/downfall/tree/main/POC  
  
  
作为Intel的一生之  
友敌，AMD在CPU  
性能漏洞上从来不落后，这次USENIX Security会议上，苏黎世联邦理工的研究人员提出了所谓的“盗梦攻击”也就是“Inception Attack”（请问大家，陀螺最后到底停下来了没有^_^）。虽然欧洲的研究人员比较朴实，没专门搞一个网站，但是他们在自己的团队主页上仍然有相关的介绍。  
> https://www.usenix.org/system/files/usenixsecurity23-trujillo.pdf![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21H0zesURJwXtt5ic316bXZY0kOPEvPDFqUpjVvjZT2jMxviaoBiclnaT1zERKp7wcBYIG1wfer7uboWQ/640?wx_fmt=png "")  
  
  
> https://comsec.ethz.ch/research/microarch/inception/![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21H0zesURJwXtt5ic316bXZY0bPWiaBDwe6IxH8v7Fr2gKT9yuiaj8nfXWyf7VCGu20Ot8iafS5KMLDiaqg/640?wx_fmt=png "")  
  
  
  
实际上，Inception攻击可以追溯至本文作者提出的名为“Phantom speculation”的攻击（CVE-2022-23825），而Phantom攻击的研究成果发表于MICRO 2023会议上（论文 https://comsec.ethz.ch/wp-content/files/phantom_micro23.pdf 在此），作者发现AMD（和Intel）的CPU在流水线执行的很早期阶段就进行了预测执行，Phantom攻击利用这一点，在差不多任意指令（而不是分支执行指令）上触发预测执行并获取信息。  
  
在Phantom攻击的基础上，作者又发展出了一种叫做“Training in Transient Execution”的技术，从而实现了Inception攻击。这里面要了解的基础知识，是在预测执行中，硬件有一些 microarchitectural branch prediction buffer——包括Return Stack Buffer（RSB）和Branch Target Buffer（BTB）等。如果这些buffer被劫持，那么攻击者就可以实施针对 transient execution 的控制流劫持！而Training in Transient Execution这种技术就是利用各种技巧，来操控RSB和BTB，最后完成劫持，然后泄露信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21H0zesURJwXtt5ic316bXZY0fNibVJbsacjDIFfg8TvP9ZSZkCsEs4Rq0GeeicoqcQYLm70XR9axSibibA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21H0zesURJwXtt5ic316bXZY0CRuQTtJqegtAB7YiaTzThPcEcaeRnztbicf1wspia3ZR5Qx3VMpicRxGog/640?wx_fmt=png "")  
  
话不多说，我们再来看一个演示视频（然后大家自己去读论文）：  
  
  
最后说一下Inception攻击的可行性，作者表示，在实际场景中，攻击泄露信息的速度是每秒39字节，这一只需要非常短的时间就可以泄露用户口令（假设明文存储在内存中）或者私钥信息（哪怕是数百字节的RSA key）。  
  
好了，今天的阅读推荐就到这里，差不多也到了USENIX Security开幕式的时间了。大家关注今年的会议，千万不要忘记在会议的第二天下午（北京时间周五上午）关注我们的Medusa Attack哦~~~  
  
  
