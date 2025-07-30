#  【漏洞复现】九思oa之奇怪的sql注入  
原创 跟着斯叔唠安全  跟着斯叔唠安全   2025-06-12 23:00  
  
免责声明  
：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
1  
  
Start  
  
指纹  
```
body="/jsoa/login.jsp"
```  
  
  
2  
  
Action  
  
依旧是  
盲注  
，不过，今天不是sleep(3)，而是sleep(0.0003)。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UZqV8ShtHfb17Lk0J05Q9s4hc1OZCfwDhXV3sneVPib4tfGPDHbRibxuXKvKWad67gcjHq7zrEl3qWA/640?wx_fmt=png&from=appmsg "")  
  
造成这样的原因是由于其代码层面的sql语句造成的，大概意思就是  
前半部分会查询数据库有多少条，  
然后每一条都会执行一下这个sleep，这也就导致了  
  
sleep(0.0003)延迟能够出了  
sleep(3)的效果。  
  
  
3  
  
End  
  
🚀 **新圈子上线 | 高质量安全内容持续更新中！**  
  
我最近在纷传上建立了一个全新的安全技术圈子，主要聚焦于 **WEB安全、APP安全、代码审计、漏洞分享**  
 等核心方向。目前圈子刚刚建立，内容还不算多，但会**持续高频更新**  
，只分享真正有价值、有深度的干货文章。  
  
📚 圈子中包含：  
- 高质量原创或精选的安全技术文章  
  
- 公众号历史付费内容免费查看（如：小程序RPC、APP抓包解决方案）  
  
- 一些只在圈子内分享的独家思路和实战经验  
  
- 不定期分享0/1day  
  
文章中涉及的完整POC及代码审计报告已上传至纷传圈子中，需要的师傅可以自取哈  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UaQw8cfe5zo87XFXicicayuia9gvdmBnX6lOnSygn4NFJlzqeyxyes0uIYicDwGwh3rbAYicdwYFhK3Ang/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
