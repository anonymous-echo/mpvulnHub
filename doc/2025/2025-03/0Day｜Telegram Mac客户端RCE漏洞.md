#  0Day｜Telegram Mac客户端RCE漏洞   
原创 校长  不懂安全的校董   2025-03-22 19:21  
  
## 0x01 前言  
  
说来搞笑，这个漏洞我是如何发现的呢？最近所谓的AI Agent智能体很热门，其中“Manus”最为出名。于是乎我去通过朋友的渠道搞了一个邀请码开始尝试使用。一开始觉得让它写东西很方便，不过他既然它能够执行操作，于是乎我开始让它自己学习  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfiaz5ib3WEvVr5PjacERPqickzDRPId4ERE9ejpib6hIRVQh6n42cxibLAo6G8PrG5o1Xqd8YnNguo5S5w/640?wx_fmt=png&from=appmsg "")  
  
并且我还给它投喂了几篇公开的MacOS系统的RCE漏洞让它能够快速学习。通过长时间的等待让它自己学习，并且在学习的过程中，它还分析出了一个未公开的1Day并且给了具体的POC以及EXP。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfiaz5ib3WEvVr5PjacERPqickzer4hs9tWSxomRgTliaImVmlDpRva1A9F9z8Bzo1NIMTibbQwex3xR6rQ/640?wx_fmt=png&from=appmsg "")  
  
我这边也和别的产商在联系，他们愿意花费50k~80K收购这个漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfiaz5ib3WEvVr5PjacERPqickzQk9UVfEPn5nNrOAK2DM9vfgPHJ4fwDQe8veSNNQFGszR4qsyscZibcg/640?wx_fmt=png&from=appmsg "")  
## 0x02 漏洞描述  
  
这个Telegram的MacOS系统的RCE，是通过Manus学习后研究出来的绕过方法，其实是MacOS自己漏洞但是也绕过了Telegram原先该漏洞文件后缀的限制。所以Telegram才会产生这个RCE。并且该漏洞在最新版本的Telegram的MacOS客户端中依旧能成功复现。  
## 0x03 漏洞证明  
  
绕过了Telegram的限制，并且下载后没有Quarantine 属性，点击即可触发RCE。由于这个漏洞是绕过的一个特殊的后缀，所以录屏的话会暴露POC，于是我这里采用截图的形式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfiaz5ib3WEvVr5PjacERPqickzZ8USZnseXwxvfobzY1ibXCwoNQ9wf1DE77RIkHrZlq4JO2pwP0rRepg/640?wx_fmt=png&from=appmsg "")  
## 0x04 结尾  
  
承接红蓝对抗、安全众测、安全培训、CTF代打、CTF培训、PHP / JAVA / GO / Python 代码审计、渗透测试、应急响应、免杀/远控开发、二进制漏洞挖掘、Web3安全服务、智能合约代码审计 等等的安全项目，请联系下方微信。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icefLCXrhxfiaMBD7vPDVIRcdPLqmc3et5ibjUNW7uKvichxflshtDKDdL0mBFZHl83rdhYDicM46qvrKbMGwSgoatw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
