#  G.O.S.S.I.P 阅读推荐 2024-05-27 智能合约漏洞检测到底行不行？   
原创 G.O.S.S.I.P  安全研究GoSSIP   2024-05-27 20:09  
  
今天要为大家介绍的是IEEE S&P 2024的论文Large-Scale Study of Vulnerability Scanners for Ethereum Smart Contracts，一看就知道是一项   
讨伐 分析当前区块链智能合约漏洞检测工具有效性的研究工作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21EbJmPN0bAlkxDcEiaiblquCTHNpybepotKAoo4tnOcI5Bicq23gRTnjVpWv0gyjHpsicoEIFeV0M3udQ/640?wx_fmt=png&from=appmsg "")  
  
作者来自德国维尔茨堡大学（University of Würzburg），大家知道维尔茨堡历史上出过哪些名人吗？近代原子物理学史上两个大名鼎鼎的人物——伦琴和海森堡就是维尔茨堡人。看起来这个地方的人特别能够看穿，所以今天我们要看看这篇论文的作者是如何看穿当今各种区块链智能合约漏洞检测工具的。  
  
这篇论文主打一个straightforward风格，上来二话不说就找了14个基于源代码的漏洞检测工具和4个基于字节码的漏洞检测工具来进行测试，它们分别是：  
> 基于源代码的漏洞检测工具  
  
- Slither  
  
- SmartCheck  
  
- Maian  
  
- Oyente  
  
- Artemis  
  
- Osiris  
  
- Securify2  
  
- Mythril  
  
- TeEther  
  
- ConFuzzius  
  
- Smartian  
  
- sFuzz  
  
- GNNSCVulDetector  
  
- MANDO-GURU  
  
> 基于字节码的漏洞检测工具：  
  
- Vandal  
  
- Maian  
  
- Oyente  
  
- Mythril  
  
在这里插一句，其实如果你也想去做类似的实验，并不需要大费周章，只需要参考一个叫做SmartBugs的项目（最早来自ICSE 2020论文）就好了，通过SmartBugs框架就可以很方便的运行一大堆漏洞检测工具，像VirusTotal那样得到一堆检测结果，然后自行判定。  
> https://smartbugs.github.io/![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21EbJmPN0bAlkxDcEiaiblquCTLxDX3Bg92LygRIX4spO1I2aQOAMmFydvdqCL3pSffVicjbKSiaTlAwLg/640?wx_fmt=png&from=appmsg "")  
  
  
  
回到今天的论文，作者既然是分析区块链上的漏洞检测工具，当然也要使用到区块链的共识这个概念。实际上作者就是拿18个工具来一起测试，然后看到底这些工具能不能针对某个具体的问题达成共识——也就是说所有工具都认定代码某处有问题。这个方法论很简单，在介绍具体的测试结果前，我们先看看作者是怎么去建立实验数据集（特别是ground truth）的。  
  
既然涉及到基于源代码和基于字节码的漏洞检测工具，那么测试数据集自然也分成了有源代码的智能合约集合（Source Code Dataset，SCD）以及无源代码（只有EVM字节码）的智能合约集合（Bytecode Dataset，BCD）。作者的SCD包含了77219个不同的合约，BCD则是包含了4062844份字节码合约。  
  
作者还特别强调，本文的一个重点检测项目是reentrancy漏洞，因此他们特别针对这个方面做了准备：通过对SmartBugs Wild Dataset（还是前面提到的SmartBugs项目，里面包含了47398个有源码的合约，但是有点老，是2020年建成的数据集）中的合约进行预编译，生成对应的AST然后根据AST来去重，得到了22237/47398个合约，然后把里面包含call，send和transfer类型的函数（只有包含这些函数，合约才能被外部调用）的合约挑出来，然后花了四个人月的工作量（让两个master student干苦力，一个博士生做监工，《生活大爆炸》歧视警告！！！），标记了总共13773个可能有reentrancy漏洞风险的合约。  
  
此外，作者还从下面五个来源收集了373个经过安全研究人员分析并标注过的智能合约：  
- “Quantstamp Security Audits” https://certificate.quantstamp.com/  
  
- “OpenZeppelin Security Audits” https://blog.openzeppelin.com/security-audits/  
  
- “Trail of Bits Security Audits” https://github.com/trailofbits/publications/tree/master/reviews  
  
- “ConsenSys Audits” https://consensys.net/diligence/audits/  
  
- “CertiK Audits” https://www.certik.com/  
  
有了这些数据集，剩下的任务就是让工具们撒欢干活了，不过作者也为我们总结了一下各家工具的特色：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21EbJmPN0bAlkxDcEiaiblquCTeDh0ia4xjJCgeZTIJ54p27PVFrt33tficIAXLqpvnDYYbFVicZibfW2xYQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21EbJmPN0bAlkxDcEiaiblquCTVJZaI5icWRmp158yCXeY2BM4ibE5qQ4ABicX0lsVwmyOI599tLhczhibqQ/640?wx_fmt=png&from=appmsg "")  
  
在实验结果这一部分中，我们要吐槽一下这篇论文的两个比较糟糕的点：首先，作者只是针对某一类型的漏洞（例如TxOrigin），把所有工具的检测结果（发现的漏洞数量）和它们的交集用下面这种风格的图画出来，以致于论文里面充斥着圆点和竖线（捂脸），然后却没有针对具体漏洞的分析（比如针对某个合约的某个漏洞，为什么有些工具检测出来了，有些工具没法检测），反而去关心F1 score和Accuracy这些数字，这种抹掉个体的细节，只关心宏大叙事的话术，过于讨好审稿人而不在意读者的感受了吧；其次，所有这些图都不是矢量的，放大了看让强迫症的读者十分难受！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21EbJmPN0bAlkxDcEiaiblquCTwWMOFjWKzXx52rLZXIk3EAEQ6TBCfQdM0sicKLQicicumsy9ibNk3Q9eSQ/640?wx_fmt=png&from=appmsg "")  
  
总之，读完这篇论文，大家可以看到，在本领域其实还有非常多可以改进的空间，哪怕不做改进，而是去进行更深入调查，这篇论文也留下了很多空白让我们去填充！  
> 论文：https://www.computer.org/csdl/proceedings-article/sp/2024/313000a220/1WPcYKIy2NG数据集：https://github.com/sss-wue/sc-study/ （会议都结束了，还没公开，这种行为以后应该写进区块链里面公开处刑）  
  
  
  
