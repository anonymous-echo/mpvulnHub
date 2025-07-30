#  锐捷网络-EWEB系统auth接口存在远程命令执行漏洞 附POC   
2025-2-11更新  南风漏洞复现文库   2025-02-11 14:42  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 锐捷网络-EWEB系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
锐捷网络-EWEB系统  
## 2.漏洞描述  
  
锐捷网络-EWEB系统auth接口存在远程命令执行漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
锐捷网络-EWEB系统  
  
![锐捷网络-EWEB系统auth接口存在远程命令执行漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3bKHkgDiauX9FNya0VM8l3bBePxVTnKH8sjliaOYlRLWNibMKADAC0HnKy46WhZkKZWc4UDBu4Ahrjfw/640?wx_fmt=png&from=appmsg "null")  
  
锐捷网络-EWEB系统auth接口存在远程命令执行漏洞  
## 4.fofa查询语句  
  
body="cgi-bin/luci" && body="#f47f3e"  
## 5.漏洞复现  
  
漏洞数据包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKHkgDiauX9FNya0VM8l3bBrP0O2VHHslPsMicSLdpLbxwsO0JLPxouZuf4BOibcPDenl0ZRibaYJwsw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKHkgDiauX9FNya0VM8l3bBVNatNkDrH9Jfg2UaLT7SibkZO5jdYJ6ogTW7QtMlvaKEhjdrkRSQXibg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKHkgDiauX9FNya0VM8l3bBXJso7SrJHdP7iaOGGuOblmtHvqpk7A6VBK97fQicdUsedlSJMia0PPUnA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKHkgDiauX9FNya0VM8l3bBxZtmXMFZO3GS6oibRtzlCYx4zGQ8vPcia9qtWQM0HvcNicXCibm23UA7yw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKHkgDiauX9FNya0VM8l3bBqPyXMSRtcCpxdvw4l4ySKm1MXxtajxRgLg1lNKE3hgxmCGfyibtbOlQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKHkgDiauX9FNya0VM8l3bBU1M4mHv71OibqQV6uYQEg5icpjSYpNbEAvrWEtnWWs4vXx9ibDAXJuhqA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKHkgDiauX9FNya0VM8l3bBjvxLb9xDOmDQiampINc1LJYL8pMpuqqZicG0tv6ibGjaCRT3gDPN9OG3A/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
