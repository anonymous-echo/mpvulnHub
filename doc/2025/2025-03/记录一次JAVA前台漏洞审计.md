#  记录一次JAVA前台漏洞审计   
知名小朋友  进击安全   2025-03-08 16:37  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
  
**一、前言**  
  
      
好久没有进行自己更新相关的文章了，今天来更新一篇对学员的一个JAVA源码的审计过程，并且成功审计出来漏洞的一个案例。  
  
二、事情过程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8PGMR0estITKqem6LIzgeYTpKW8F8s1rWXnQNHq3ymPcD0Lbp9wstVxA/640?wx_fmt=jpeg&from=appmsg "")  
  
    某天晚上，学员直接发来一个源码，顺带了一句话：《有个JAVA的帮我看看有没有前台洞》，我**是神啊，我给你看看有没有漏洞，我自己审出来我自己偷偷藏着不好吗！，但是秉持着顾客就是上帝的原则，还是看看吧。  
  
二、审计过程  
  
      
将代码载入工具进行查看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8P6TvjfcibxsAYWUruCTlTiaAeFtZNDYJbvWDTNlHrlJFiaLyZB7QScG7Iw/640?wx_fmt=png&from=appmsg "")  
  
其中我们查看web.xml相关内容，既然是前台漏洞，先来寻找相关的鉴权相关的代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8PISN559nKUqRjFnOPLZE0fRI1MiaPiakb7ibgVqhuRcFw2D0ne6R5hwlEA/640?wx_fmt=png&from=appmsg "")  
  
在看到上述过滤器的时候，发现其中使用的是Struts2框架使用的，于是我们转换文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8PDjDjOdbTVpvCID6ftProDaQTuPuj3twDsClvXBFMlnlSda8icmxdoLA/640?wx_fmt=png&from=appmsg "")  
  
这么多文件，但是我们也没有实际可以进行测试的网站，这里发现存在一个文件叫做login.jsp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8PJ88QVy2JPYgmc2zHbZAIibZ1hKGhUAPlkp6JIsKQ86vwVtW2Jw8MicuQ/640?wx_fmt=png&from=appmsg "")  
  
发现了它的公司名称，于是使用FOFA进行搜索相关指纹，得到了目标网站。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8PbDnQSZ79QOb1iciaZicnuPht5sK8TaB6xw74R1cMP8qvDjhV9iahgm2fGA/640?wx_fmt=png&from=appmsg "")  
  
这里我们可以得到system为后台路径，并且我们在代码中进行验证。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8P3h8cmensERsDlLiatp8eUupZTXJe1WPqmAMVCa9wXAIEn0ABOibRphnA/640?wx_fmt=png&from=appmsg "")  
  
在文件当中发现了存在过滤器，这里我们进行查看相关过滤器是否进行了权限验证。  
  
（但是不在这个过滤器当中，在另外一个）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8PqCiaYuC6ERl4lNfPoyPGbicyrrC9J57op8dJEqKHdBoGgLjfh9M5UUibw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8Po5kHjLtbU9PINaWYialGq4nFhHAxzYYoBdlTabzB9Z3RKicibIZgIvoCw/640?wx_fmt=png&from=appmsg "")  
  
这种代码我该如何绕过，但是这里还是老方法吧，寻找不鉴权的地方。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8PRNtVNiaoScWQ16YaKolV2DxJCcyJR6UWRozJrHWbu8n9mh3orqYxovA/640?wx_fmt=png&from=appmsg "")  
  
对他进行代码审计，最终发现一处前台SQL注入漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8PnuFwEZD6cWYfUm5TYFI9cXqsGNVN1nfXNRyL0iaibh3TiayEWobrI9b0w/640?wx_fmt=png&from=appmsg "")  
  
这么明晃晃的注入，于是收工。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8PPyuS5FfrSHuuWBH9TToq3OYLW4eB3Jl1hyV2WJpFvwmgbib1KeCsZGA/640?wx_fmt=jpeg&from=appmsg "")  
  
这里就不进行漏洞利用证明了，直接sqlmap就可以跑出来。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhWATkp4YmDynYwvDLWLfd8PmHPB6ia2C2ovib2p6uDSYrMsmxWMLYSjHVjlicicdLQBAicZDorGlxUH8AA/640?wx_fmt=jpeg&from=appmsg "")  
  
三、明广  
  
      
代码审计第四期马上开启，目前已经完成小程序逆向方面的课程录制，想要学习代码审计课程的师傅们可以速度联系我了，NET、JAVA、PHP、APP逆向、小程序逆向、WEB逆向、漏洞挖掘案例分享、冰蝎&哥斯拉魔改均有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
  
