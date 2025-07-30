> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MzM3NTQ5MA==&mid=2247484605&idx=1&sn=0e380428ba92aad096e73a4416c9f1b5

#  信息收集之WEB页面开发架构识别从而快速发现是否有已知漏洞  
原创 OneDay一卒的老付  老付话安全   2025-06-27 12:24  
  
## JS前端架构  
  
什么是JS渗透测试？  
  
在Javascript中也存在变量和函数，当存在可控变量及函数调用时就会发生参数漏洞  
  
JS开发的WEB应用和PHP，JAVA,NET等区别在于即使没有源代码，也可以通过浏览器的查看源代码获取真实的点。获取URL，获取JS敏感信息，获取代码传参等，所以相当于JS开发的WEB应用属于白盒测试（默认有源码参考），一般会在JS中寻找更多的URL地址，在JS代码逻辑（加密算法，APIkey配置，验证逻辑等）进行后期安全测试。  
  
前提：Web应用采用后端或前端语言开发  
  
后端语言：php、 java 、python、 .NET 浏览器端看不到真实的源代码  
  
前端语言：JavaScript(JS)和JS框架 浏览器端看到真实的源代码  
  
如何判断js开发应用？  
1. 插件wappalyzer  
1. 源程序代码简短  
1. 引入多个js文件  
1. 一般有/static/js/app.js等顺序的js文件  
1. 一般cookie中有connect.sid  
JS安全问题  
    源码泄漏=代码注释部分泄露是某个开源的源代码  
    未授权访问=JS里面可以分析更多的URL访问，确定接口路径  
    敏感key泄漏=JS文件中可能配置了接口信息（云应用，短信，邮件，数据库等）  
    API接口安全=（代码中加密提交参数传递，可以获取更多的URL路径）  
  
流行的Js框架有那些？Vue、 NodeJS、 jQuery、 Angular等  
  
如何获取更多的JS文件？  
    手工-浏览器搜索（F12 或右击检查，右上角三个点>更多工具>搜索）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKb2wsWzy9MZSqFBUhmMO0cGv00w4oJzLeIjMINicOj0rBwh3NcRBzGk0vCTrrmIPIOly0NQ7XHGQeMWic3iaB4SQ/640?wx_fmt=png&from=appmsg "")  
  
  
    半自动-Burpsuite插件  
    工具化-各类提取&FUZZ项目  
## JS前端开发框架分析  
  
如何快速获取价值信息?   浏览器 CTRL+F搜索关键字  
  
    src=  
  
    path=  
  
    method:"get"  
  
    http.get("  
  
    method:"post"  
  
    http.post("  
  
    $.ajax  
  
    http://service.httppost  
  
  
http://service.httpget  
  
通过Chrome插件判断网站前端框架  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKb2wsWzy9MZSqFBUhmMO0cGv00w4oJzyAkwdibibOOTeZxRJLJT7bfVrXdj1ibPzMicn8bLLH3hCpIkOndNKvd1LQ/640?wx_fmt=png&from=appmsg "")  
  
通过浏览器上的文件分析，引用了大量的js文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKb2wsWzy9MZSqFBUhmMO0cGv00w4oJzFSYWEJLzHdia0nibHJjQAySZuroopDS9xrQuLibKvCA2sUJqbibIUYrBlg/640?wx_fmt=png&from=appmsg "")  
## 前端架构-半自动Burp分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKb2wsWzy9MZSqFBUhmMO0cGv00w4oJzgIjCKeibRZYfUsrtxicgXDecYo0qThQv8WibMXkGrxQ54l0jFN4ELOMJA/640?wx_fmt=png&from=appmsg "")  
## 前端架构-自动化项目分析  
1. **Jsfinder 工具**  
https://github.com/Threezh1/JSFinder**一款用作快速在网站的js文件中提取URL，子域名的工具（不推荐使用）**  
- 使用语句：python JSFinder.py -u https://px.gtxy.cn/np/#/login  
1. URLFinder-从JS中提取URL或者敏感数据（*）  
https://github.com/pingc0y/URLFinder  
  
一款用于快速提取检测页面中JS与URL的工具。功能类似于JSFinder  
1. JSINFO-SCAN-从表现中JS中提取URL或者敏感数据  
https://github.com/p1g3/JSINFO-SCAN  
  
递归爬取域名(netloc/domain)，以及递归从JS中获取信息的工具  
1. FindSomething-从表现中JS中提取URL或者敏感数据-推荐（*）  
https://github.com/momosecurity/FindSomething  
  
该工具是用于快速在网页的html源码或js代码中提取一些有趣的信息的浏览器插件，包括请求的资源、接口的url，请求的ip和域名，泄漏的证件号、手机号、邮箱等信息。该工具是用于快速在网页的html源码或js代码中提取一些有趣的信息的浏览器插件，包括请求的资源、接口的url，请求的ip和域名，泄漏的证件号、手机号、邮箱等信息  
1. ffuf-FUZZ爆破找到更多的js文件分析更多的信息（*）  
https://github.com/ffuf/ffuf  
  
https://wordlists.assetnote.io  
  ---字典下载(很丰富)  
  
功能强大的模糊化工具，用它来FUZZ模糊化js文件。  
- 语法：
```
ffuf.exe -w js字典.txt -u https://m.xjggjy.com/FUZZ -t 200
```

  
1. Packer-Fuzzer-针对JS框架开发打包器Webpack检测（*）  
https://github.com/rtcatc/Packer-Fuzzer  
  
一款针对Webpack等前端打包工具所构造的网站进行快速、高效安全检测的扫描工具  
  
语法：python packerfuzzer.py -u   
http://1.15.51.4/  
  
使用方式：首先利用插件获取查看杂项为Webpack的网站  
  
直接将网址粘贴至语法后面等待扫描结束  
  
在reports目标目录下，出现综合网址，word等文件  
  
一款针对Webpack等前端打包工具所构造的网站进行快速、高效安全检测的扫描工具webpack是一个打包工具，他的宗旨是一切静态资源皆可打包。有人就会问为什么要webpack？webpack是现代前端技术的基石，常规的开发方式，比如jquery,html,css静态网页开发已经落后了。现在是MVVM的时代，数据驱动界面。webpack它做的事情是，分析你的项目结构，找到JavaScript模块以及其它的一些浏览器不能直接运行的拓展语言（Scss，TypeScript等），并将其打包为合适的格式以供浏览器使用。  
  
  
