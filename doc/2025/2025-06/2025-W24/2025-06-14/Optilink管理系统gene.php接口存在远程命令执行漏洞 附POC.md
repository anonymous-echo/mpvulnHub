> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247488604&idx=1&sn=14924432f473c81796e50ec5cb00b963

#  Optilink管理系统gene.php接口存在远程命令执行漏洞 附POC  
2025-6-14更新  南风漏洞复现文库   2025-06-14 02:07  
  
   
  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## Optilink简介  
  
微信公众号搜索：南风漏洞复现文库  
该文章 南风漏洞复现文库 公众号首发  
  
Optilink管理系统  
## 2.漏洞描述  
  
Optilink管理系统是一款基于现代通信技术，用于对不同领域的设备、生产流程或环境进行实时监控、数据可视化以及远程控制，以实现优化管理和提高效率等功能的软件系统。Optilink管理系统gene.php接口存在远程命令执行漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
Optilink管理系统  
  
![Optilink管理系统gene.php接口存在远程命令执行漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3bmaBEDibfG75oQRicVQRzXBicUbvxhqARC6b2YeMPY6xICeyz8HLRkKB0If0iaBeDu3GdbNmEeBhLpRA/640?wx_fmt=png&from=appmsg "null")  
  
Optilink管理系统gene.php接口存在远程命令执行漏洞  
## 4.fofa查询语句  
  
body="/html/css/dxtdata.css" && title="login"  
## 5.漏洞复现  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bmaBEDibfG75oQRicVQRzXBic06Nj5M1TKNzWRfjG6ptKLSrrEQdRwwYCmnAicE9pehdIhZ66lzoibDxw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
生成的文件路径：/cgi/fsystem/739444.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bmaBEDibfG75oQRicVQRzXBichgQPpVh07Ay6bymGYoMPZibiadSImxQ6NTShMz5zjpIQL9WCzHmNeNTg/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bmaBEDibfG75oQRicVQRzXBiceB4XYrBt0cBtzmX0ibgvPWWoybqFyibXu4B4OHYXg4EA1t9eE07yX3Dg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bmaBEDibfG75oQRicVQRzXBicYjXO2Vs0DzwUOhdNppMaxWjLm0BFribdjTIrhGFicicyhRyegW4M3CBiaQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bmaBEDibfG75oQRicVQRzXBicaYTwQPBKeEkbGjO38A5nGxw05gsenOdOSlSsyrbibysSKiaQhMp2yQmw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bmaBEDibfG75oQRicVQRzXBic16SsOtz9DibGhj8um0pJYa3a6tvvRgNWAbJQuhQF28icXKv2XtxseVBw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bmaBEDibfG75oQRicVQRzXBicWwPZ5HTOF26my46DWj93wRDfMLHWGtu6NRnPSt66C2kCxdxbaVLltg/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
   
  
  
  
