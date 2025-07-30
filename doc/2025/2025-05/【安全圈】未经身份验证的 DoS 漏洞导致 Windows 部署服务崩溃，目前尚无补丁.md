#  【安全圈】未经身份验证的 DoS 漏洞导致 Windows 部署服务崩溃，目前尚无补丁   
 安全圈   2025-05-07 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![预授权 DoS，Windows 部署服务](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaicPuZeE6vVicfkM011lA5jb1jFuNxTAiaN7FMr46iapsO3BJDVgPkxhNVzAwszOwpA7Ouv6iawKgUk6g/640?wx_fmt=other&from=appmsg "")  
  
根据安全研究员  
Peng的详细技术分析，Windows 部署服务 (WDS) 中新披露的一个拒绝服务 (DoS) 漏洞可能引发远程、未经身份验证的崩溃，威胁企业网络安全。该漏洞于 2025 年初被发现，并已向微软负责任地披露。攻击者可以利用该漏洞利用伪造的 UDP 数据包耗尽系统内存，导致服务器在几分钟内完全无响应，且无需任何身份验证或用户交互。  
  
“我们演示了 WDS 中的远程 DoS，攻击者可以在无需身份验证（预身份验证）或用户交互（0-click）的情况下破坏您的 WDS 网络  
，”Peng在他的报告中解释道。  
  
问题的根源在于 WDS 使用基于 UDP 的 TFTP 服务（端口 69）通过 PXE 启动来传送 Windows 安装映像。当客户端连接服务器时，WDS 会分配一个 CTftpSession 对象。然而，可创建的会话数量没有限制。  
  
报告指出：“核心问题在于 EndpointSessionMapEntry 对会话数量没有限制。攻击者可以伪造客户端 IP 地址和端口号，反复创建新会话，直到系统资源耗尽  
。”  
  
在运行具有 8GB RAM 的 Windows Server Insider Preview 的测试环境中，Peng 只需发送大量具有随机源地址和端口的欺骗性 UDP 数据包，便可在 7 分钟内使整个系统崩溃。  
  
Peng 概述了一个简单的攻击策略，该策略需要：  
- 使用随机源 IP 和端口欺骗 UDP 数据包。  
  
- 将数据包发送到端口 69 上的目标 WDS 服务器。  
  
- 允许 WDS 在内存中创建和存储无限的会话对象。  
  
尽管 Peng 出于道德原因只提供了伪代码，但该漏洞利用技术实现起来却很简单，只需要在运行 Ubuntu 或类似操作系统的攻击者机器上编写基本的脚本即可。  
  
 该漏洞于 2025 年 2 月 8 日报告给微软，并于 2025 年 3 月 4 日得到确认。然而，微软后来拒绝修补该问题，并于 4 月 23 日表示其“不符合安全服务标准  
”。  
  
Peng严厉批评了这一决定：“我们认为这仍然是他们 SDL 栏中的一个重要的 DoS漏洞，我们在与微软就此案进行沟通时感到非常难过  
。”  
  
他强调，这是一种零点击攻击，可以远程瘫痪基于 PXE 的部署基础设施，这对于任何依赖 WDS 的组织来说都是一个关键问题。  
  
由于微软尚未发布修复程序，Peng 提出了明确的建议：“为了保护您的 PXE 网络免受此威胁，请不要使用 Windows 部署服务  
。”  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】微软Skype正式停止运营 你用过吗？](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069467&idx=1&sn=ce2b90f7231009359c5ce6dc5691232c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】突发！欧盟再开天价罚单！TikTok被罚5.3亿欧元！数据安全成焦点](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069467&idx=2&sn=a89f67a37b46955963eed7b0f491fcc0&scene=21#wechat_redirect)  
  
  
  
[【安全圈】iOS 出现新严重漏洞，仅需一行代码即可导致 iPhone 崩溃](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069467&idx=3&sn=24714661691469cf4a95022a439d1f5f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】CVE-2025-21756：Linux 内核漏洞如何导致完全 root 权限利用，PoC 发布](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069467&idx=4&sn=82381e377828001cba5f1b8b0cd0bdf1&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
