#  从 Rebuild 企业级系统代码审计 SSRF 漏洞。   
 闪石星曜CyberSecurity   2025-06-04 04:07  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgwNVTialU2Iq0hN53OR3Xgo7uyfASIicOAsQn2NfEStOyF8miboOpE7WEw/640?wx_fmt=gif&from=appmsg "")  
  
本篇为代码审计系列SSRF漏洞理论篇第五篇，看完本篇你将掌握关于SSRF漏洞的代码视角原理剖析、基础挖掘漏洞核心能力，看完如有技术错误欢迎评论区指正。  
- 漏洞原理  
  
- 业务视角DEMO代码  
  
- 漏洞校验DEMO代码  
  
- 实战审计案例  
  
  
  
**SSRF漏洞**  
  
一  
  
漏洞原理  
  
1.1业务原理视⻆  
  
用户使用电脑浏览器操作企业Web站点某些功能的背后逻辑业务逻辑是在本地或远程加载资源，例如：加载图片资源等。企业用户使用协议请求正常链接进行加载，恶意用户利用远程加载功能用于探测其他资产，利用资产敏感信息进行下一步攻击活动。  
  
  
1.2漏洞原理视⻆  
  
SSRF其技战术是  
初始访问 | QT1190.021 SSRF  
，主要是在加载远程链接代码逻辑过程中未对加载路径进行校验，导致通过该漏洞利用应用主机向其它地址发起请求，导致数据泄露或攻击内网服务。  
  
二  
  
业务视角DEMO代码  
  
常见SSRF漏洞涉及很多协议http、https、file、ftp、mailto、jar、netdoc；  
  
请求网络加载资源功能流程如下：  
  
    初始化网络连接  
  
    请求网络资源  
  
    获取响应内容  
  
  
2.1HttpClient  
  
HttpClient是Apache Jakarta Common下的子项目，可以用来提供高效的、最新的、功能丰富的支持HTTP协议的客户端编程工具包，并且它支持HTTP协议最新的版本和建议。HttpClient实现了HTTP1.0和HTTP1.1。也实现了HTTP全部的方法，如：GET, POST, PUT,DELETE, HEAD, OPTIONS, TRACE  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgfia5XILcT8iaSdNhNXbZD7lUmXOY0DF65HCIhzgNhS14eQH3cECb1ttw/640?wx_fmt=png&from=appmsg "")  
  
  
2.2RestTemplate  
  
RestTemplate是从Spring3.0开始支持的一个HTTP请求工具，它提供了常见的REST请求方案的模版，例如GET请求、POST请求、PUT请求等等。从名称上来看，是更针对RESTFUL风格API设计的。但通过他调用普通的HTTP接口也是可以的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicg4oUWpVGW4iaGdmXoxUxTkRKDHwsMjzKJVgNdnR5ibfCQf0RYhkpOufYg/640?wx_fmt=png&from=appmsg "")  
  
  
三  
  
 漏洞校验DEMO代码  
  
针对业务代码多种方式做SSRF操作，主要是针对java中网络请求类进行关键词"搜索"。  
  
HttpRequest、Jsoup.connect、getForObject、RestTemplate、postForObject、httpclient、httpasyncclient、java.net.URLConnection、openConnection、java.net.HttpURLConnection、openStream、Socket、java.net.Socket、okhttp、OkHttpClient、newCall、ImageIO.read、javax.imageio.ImageIO、HttpRequest.get、jsoupJsoup.connect  
  
SSRF漏洞限制：为了修复 SSRF 漏洞并提高代码的安全性，可以采取以下措施：  
  
- 限制允许访问的域名或 IP使用白名单机制，只允许访问特定的域名或 IP 地址。例如，只允许访问https://www.baidu.com                    https://example.com。  
  
-验证 URL检查传入的`url`是否符合预期的格式（如必须以https://开头）使用正则表达式或 URL 解析库验证 URL。  
  
-使用安全的 RestTemplate 配置`RestTemplate`以限制其行为，例如禁用重定向或设置超时。  
  
3.1RestTemplate限制重定向行为  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgQFhBWwia2xRqoqERlILvULZSCd42yjLOBXSqtmibYuzEsICtoEyZVE6Q/640?wx_fmt=png&from=appmsg "")  
  
四  
  
REBUILD实战审计案例  
  
SSRF为白盒审计，以REBUILD项目部署后从项目代码视角到漏洞定位及漏洞调试进行讲解。主要SSRF主要为路径可控即可  
  
4.1项目部署  
  
GitHub项目地址：https://github.com/getrebuild/rebuild/releases  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgNj18AiaHoMbakRyd8bd0W8wx73icXW481ohOYbKplHyr7LCOCTvSJZcw/640?wx_fmt=png&from=appmsg "")  
  
可选择Jar包直接启动，然后下载源码进行分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicg5f9zzwsEdI7KQwAKiaTmYBwoSHmgB2tuNWuGicaFdcKTJ1gEyGJzJztw/640?wx_fmt=png&from=appmsg "")  
  
安装项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgeXqKc8HZ9AlqpkhYL2cQaP3VpwSZhUKRIRaceLPeRKwkOVCEgFQoFg/640?wx_fmt=png&from=appmsg "")  
  
4.2SSRF漏洞相关功能定位  
  
观察POM.xml文件发现引用OKHttp依赖  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgY5UrXWphnicXREThhZVicrKkIos3rXyIpcbXNk6hOGNUMvu5WlzGJibNw/640?wx_fmt=png&from=appmsg "")  
  
OKHttp关键字定位功能代码-getHttpClient  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgXdnVkMU6Z3nwQIN9E4fMEn6voJxsTteNSNwd5LnmqeUqmg8sD4Yp9Q/640?wx_fmt=png&from=appmsg "")  
  
继续使用OkHttpUtils定位搜索，所有OKHttp都会使用该包进行import  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgrRSYNjibgxhU0AwZDDFhWaQtTdoibWelicReYy0unQNVwibicqHAeMrSicaQ/640?wx_fmt=png&from=appmsg "")  
  
  
4.2.1第一处使用：OkHttpUtils  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgGOp9EgwylluctVSEHGeHo3mURKu78zbuannCOM1Jz5FgHOu9XWFYbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgKwAT8ynPg9Nz1wn714Tmp7cwhxXwZKY3OM1BgBRibjNH0k5fRkyicC1g/640?wx_fmt=png&from=appmsg "")  
  
isExternalUrl()代码跟进,发现属于HTTP或者HTTPS就直接请求了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgfBFAnBOpZUqXe0L0xDtic4anIcUeIRKecfuKsnjnHeJNodDIbdqa0cA/640?wx_fmt=png&from=appmsg "")  
  
  
4.2.2第二处使用：OkHttpUtils  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgiboBgFnFUYBRpYoWnuxcqzwZ4XOticrZ4mibkYJCuFeyBbFHj8rucUg1g/640?wx_fmt=png&from=appmsg "")  
  
分析发现这里使用isExternalUrl()进行了SSRF防护，如果是HTTP或者HTTPS则不请求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgQ0XvzLQGqwJjTKgofGwAZQL1MlEWInCJmvROKyialYdCH3cMUSgHfvA/640?wx_fmt=png&from=appmsg "")  
  
4.3漏洞测试  
  
4.3.1开启Web python服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgprV103E8woVvQDp239sbgxFETeqAVMpJlQQnviaMy3hCqfm0bHiaY4OA/640?wx_fmt=png&from=appmsg "")  
  
4.3.2直接构造参数进行HTTP请求加载  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8zn7RtM4HoTMLWbJmSpibMicgYMQlGUDqF6uibQcmwHANUhqxxsgVIx3R4fWibeibwkZ823BQYBBFWA10g/640?wx_fmt=png&from=appmsg "")  
  
END  
  
  
  
  
  
内部学员投稿。  
  
学代码审计就找闪石星曜CyberSecurity。  
  
详情可点击下方链接了解。  
  
2025版对一些课程进行了重构，丰富了知识点，并新增了一些实战课程！  
  
[《JavaWeb代码审计企业级项目实战》课程2.0升级版，新增10节实战课！依旧低至499，加量不加价！招生！](https://mp.weixin.qq.com/s?__biz=Mzg3MDU1MjgwNA==&mid=2247487386&idx=2&sn=fc36f768e8715e1b0c291519e7dad584&scene=21#wechat_redirect)  
  
  
  
