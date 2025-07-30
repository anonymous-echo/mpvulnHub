#  API测试思路及crAPI漏洞靶场复现   
原创 LULU  红队蓝军   2024-12-02 10:03  
  
#   
## 环境搭建   
  
地址：https://github.com/OWASP/crAPI  
```
curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml

docker-compose pull

docker-compose -f docker-compose.yml --compatibility up -d

```  
  
全局配置IP地址  
```
1、在 vim 中，按 Esc 键确保你在命令模式。
2、进行全局替换：将全局127.0.0.1替换成本地的IP地址 
:%s/127.0.0.1/192.168.111.130/g 

```  
## API的分类   
  
1.按照功能分类：  
```
Web API：主要用于通过网络交互的应用程序，如HTTP API、RESTful API等。
数据库 API：用于访问数据库系统的API，如JDBC、ODBC等。
图形界面 API：用于创建图形界面的API，如Java Swing、Windows API等。

```  
  
2.按照接口类型分类：  
```
开放 API：对外公开的接口，可以通过网络访问。
内部 API：仅在企业内部使用的接口，如微服务API。

```  
  
3.按照数据格式分类：  
```
JSON API：使用JSON格式的API。
XML API：使用XML格式的API。

```  
  
4.按照托管方式分类：  
```
内部 API：在本地服务器上托管的API。
云 API：在云平台上托管的API，如AWS API Gateway、Google Cloud Endpoints等

```  
  
如何发现API请求  
```
1、打开浏览器的开发者工具，通常可以通过快捷键 F12 打开。
2、切换到Network（网络）标签页，重新加载页面。
3、查看请求列表，其中可能包含网页内的API请求。这些请求通常是XHR（XMLHttpRequest）类型的请求。
4、点击请求列表中的请求，查看请求详情，可以查看请求的URL、请求方式、请求头信息和请求体信息。
5、根据请求的URL和请求方式可以确定该请求是API请求，还是页面自身的请求。
6、通过这些信息，可以分析API请求的参数和数据，进而实现API的调用和数据提取。

```  
## 关于RESTful API   
  
RESTful API (Representational State Transfer API) 是一种 Web API 设计风格和体系结构，它基于 HTTP 协议，建立在客户端和服务器之间的无状态连接上。RESTful API 将所有的 Web 资源看作是一个唯一的 URI ，并通过 HTTP 方法（GET、POST、PUT、PATCH、DELETE）来对这些资源进行操作。RESTful API 可以使用不同的数据格式（如 JSON、XML）进行通信。  
## 漏洞复现   
### 1、失效的对象级授权  
  
对象级授权是一种访问控制机制，依赖用户请求参数中的对象ID来决定访问哪些目标对象，以验证用户只能访问他们应该有权访问的对象  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcozyScVMGzLTMoLRWtBdxq4z0xRapMG5ia3Osj2Gl62ANFqN2ictBwSwA/640?wx_fmt=png&from=appmsg "")  
  
  
找到泄露用户车辆ID的接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcJVicF32kATDCMltSO0QF8iaWeHiaKQiab7q2lqGBRnk8cHrm8TibtxOH4mQ/640?wx_fmt=png&from=appmsg "")  
  
  
通过页面查找接受车辆ID 的API，替换URL中的车辆ID，成功访问到其他用户的信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfc9KdWbVN8QbbGjD1wNIrlqw56sFuNibEze4SaD2uggAUicPKIZ13BJm7w/640?wx_fmt=png&from=appmsg "")  
  
### 2、访问其它用户的机械报告  
  
发送维修报告请求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcfZMaPcyMvbRts73dbPuAmiacGibqC54MBHefnFKUDTAfibJZep44gOtkA/640?wx_fmt=png&from=appmsg "")  
  
  
抓包分析，发现请求之后，会返回一个报告访问的地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfccmTgVo589W9Sa2PohQIfpMicEibu6nQ62SqaJN7n2KqCp2FwialxGBs3g/640?wx_fmt=png&from=appmsg "")  
  
  
修改 report_id 可以查看其它用户提交的维修报告  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcD0zRPuKsCEQKpHsRicOaVyQpSORibc3Ueb2l8nZFy3CSWnsjNicWibkOHw/640?wx_fmt=png&from=appmsg "")  
  
### 3、失效的用户身份验证  
  
重置其他用户的密码  
  
首先得有email，在登录处重置密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcv9gdnia9O2R1CH19ic1lFUGa3niaT5PmicNKWiacdpUKL0bCe5YTicregZDQ/640?wx_fmt=png&from=appmsg "")  
  
  
通过抓包发现api  /identity/api/auth/v3/check-otp  是检查otp的api端点。且发现这个POST包并没有携带用于用户认证的Token  
  
OTP是指一次性密码，是指电脑系统或其他数字设备上只能使用一次的密码，有效期为只有一次登录会话或交易。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcDQXhryibBFWePs5EKRTjspiaLZ4xTkNlWONlYGlUNbGYNbHzFm0AU2ibg/640?wx_fmt=png&from=appmsg "")  
  
  
burp暴力破解，会报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcjGGzTFN2Xhxg1doLwzfOXXoKFekPQ2gyQsYkP9TI2wBHxrUNFRia1TQ/640?wx_fmt=png&from=appmsg "")  
  
  
在RESTful API在设计的时候有一个特点，它会在URL中嵌入版本号，用来保持兼容性和方便调试等。这里请求端点URL中的“v3”就表示第三个版本，可以试试换成V2版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcDaQv2G7cnbHvpbicNAjO50rUibUvY7QeaL1kibq2VobBQ89o4m9ITFscA/640?wx_fmt=png&from=appmsg "")  
  
### 4、敏感信息泄露接口  
  
访问/community/api/v2/community/posts/recent  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfczBZxPus7ubGkscFTgM23ibqmlMEichiaT0Micgc1bdSQLgr6DnYWa8EPvQ/640?wx_fmt=png&from=appmsg "")  
  
### 5、失效的功能级别授权  
  
攻击者利用漏洞将合法的API调用发送给他们不应访问的API 端点。这些端点可能会暴露给匿名用户或常规的非特  权用户。由于API更加结构化，并且更易于预测访问API的方式，因此更容易发现API中的这些缺陷（如，将HTTP方法从GET替换为PUT，或将URL中的 “user”字符串更改为“admin”）  
  
1、更改视频名字发现API端点  
  
/identity/api/v2/user/videos/31  
  
2、利用burp的intruder模块来判断是否可以使用其他方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcLcqM0jN4Dyuj6Nj9bscLnOJaDFeInW1qicMSalHH53riaDfH9fVic9W6g/640?wx_fmt=png&from=appmsg "")  
  
  
3、删除后会报一个403的错误，推测此处的user为权限控制路径，我们将user修改为admin进行尝试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcK2kO18M5ms04ib5pLtZW7N20hD7yEUgXicTtaCLrEleOwEld1p5EnHoQ/640?wx_fmt=png&from=appmsg "")  
  
  
4、/identity/api/v2/user/videos/31将user替换成admin  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcO1uBibOWN1Ouj3WCSMxukZ6xOlibVm261PWe3icWO2h22FueymcD8ia3Ow/640?wx_fmt=png&from=appmsg "")  
  
### 5、接口校验测试  
  
没有对输入的数据进行校验或者校验不完善，通常是造成漏洞的直接原因，例如一些通用的SQL注入，XSS，CSRF，甚至RCE等。这里crAPI提供了一个NoSQL注入的场景，NoSQL注入攻击也利用应用程序对用户输入不进行充分验证和过滤的漏洞，直接向数据库系统发送恶意的查询语句。  
  
1、找到验证优惠券的接口，进行nosql注入的语句尝试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcKFM0dPhviakEySf9cKtv7D5icGcDTqB1w8NPWv6uq3KWZicZBibb4ymL0g/640?wx_fmt=png&from=appmsg "")  
  
修改内容：“$ne"是MongoDB的查询操作符之一，其含义为"不等于”，用于查询某个属性不等于指定值的文档。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcvkPfAfQ7FN1qK0iafkMTNv1nyQD6e3jiaffUicHAEttQo3PGh7tkKSgXA/640?wx_fmt=png&from=appmsg "")  
  
  
得到优惠券TRAC075  
  
在获得这个优惠券以后，这里的coupon_code也可注入。  
### 6、批量分配  
  
将客户端提供的数据（例如 JSON）绑定到数据模型，而无需基于白名单进行适当的属性筛选，通常会导致批量分配。无论是猜测对象属性、探索其他 API 端点、阅读文档或在请求负载中提供其他对象属性，攻击者都可以修改它们不被允许修改的对象属性  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfc1kUiaxY4U24B9Y42ErEShXm3NS4hW6FPjtgTN7e5FnPgRXicojY5DjJw/640?wx_fmt=png&from=appmsg "")  
  
  
2.尝试修改请求方法为GET，并对参数进行修改，修改为刚测试的订单id 12  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcvExuMcdHJ5ZKYYy0mZt81NiavtKZLic2LL6vfPal7sZN195T8JJTVn5A/640?wx_fmt=png&from=appmsg "")  
  
  
3.修改请求参数为PUT，测试是否可以对已经生效的订单进行数量修改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcKsv3xxwBVuxL1pUVtdESXabW69582MNt9zZF5tB5oBbBUbPRonZMpg/640?wx_fmt=png&from=appmsg "")  
  
### 7、SSRF  
  
API的SSRF指Server-Side Request Forgery，是指攻击者利用存在漏洞的API接口发送恶意请求，以获取未授权的数据或攻击其他内部系统。攻击者通过篡改请求的URL或参数等方式向公共API发送请求，利用API服务器从指定的URL下载图片、文件等资源，实现攻击  
  
在查询车辆报告的接口，mechanic_api参数允许传递一个URL，尝试SSRF  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4c9uscsQD2ybzd4y8qFrfcjnQ6oPYfgn8X4hwbfe76AduPrWQHRpT12bDIRSvG5MguXZraWE2VwA/640?wx_fmt=png&from=appmsg "")  
  
  
参考文章：  
  
https://www.cnblogs.com/smileleooo/p/18384083#%E6%8E%A5%E5%8F%A3%E6%9D%83%E9%99%90%E6%B5%8B%E8%AF%95  
  
https://blog.csdn.net/qq_55316925/article/details/132664423  
  
  
