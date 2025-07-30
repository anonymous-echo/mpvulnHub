#  openfire鉴权绕过漏洞原理解析   
原创 HhhM  山石网科安全技术研究院   2023-06-13 10:53  
  
# Openfire是根据开放源 Apache 许可获得许可的实时协作（RTC）服务器。它使用唯一被广泛采用的用于即时消息的开放协议 XMPP（也称为 Jabber）。Openfire 的设置和管理非常简单，但是却提供了坚实的安全性和性能。  
  
Openfire存在鉴权绕过漏洞，允许未经身份验证的用户在已配置的 Openfire 环境中使用未经身份验证的 Openfire设置环境，以访问为管理用户保留的 Openfire 管理控制台中的受限页面。  
  
  
**#****0****1**  
  
  
**分 析‍‍‍‍‍**  
  
  
从  
3.10.0  
到  
4.7.4  
之间的所有版本都受到影响，在  
4.6.8, 4.7.5, 4.8.0  
中做了修复。  
  
那么以4.7.4  
为例，比对一下4.7.5  
修复的内容：  
  
其一：xmppserver/src/main/webapp/WEB-INF/web.xml  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSicsFLsmzvBcsbvku8wiblSkVc8ZlUTLicic1BJmtEuwRrdicOCuPcCSDqdko4nDgIic9k4rqhpYz1dwxw/640?wx_fmt=png "")  
  
这实际上是openfire  
的一个鉴权机制，为了将某些页面，如上图中的登陆页面从鉴权中排除，且为了更灵活而运用了通配符，但也成为了漏洞的利用条件之一，官方在修复中也把配置中的setup-*  
这一项去除了。  
  
其二：xmppserver/src/main/java/org/jivesoftware/admin/AuthCheckFilter.java  
  
比较大的改动都在这个文件中，主要集中在testURLPassesExclude  
函数中：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSicsFLsmzvBcsbvku8wiblSk1SgT64ic9r8HNbWXm7guuk20jzBIYQE2OuHMPnh7mf9uYGeDt9Q2sTw/640?wx_fmt=png "")  
  
在鉴权机制中匹配到的是setup/setup-*  
，满足  
exclude.endsWith("*")  
，同时url  
不包含..  
或者%2e  
那么就返回true  
，此时回到doFilter  
：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSicsFLsmzvBcsbvku8wiblSk8nXAEaeehib4vxGNtV0UqPNIKQX7EN5SDWMWLFXj1ibqQmVc21Ysa56w/640?wx_fmt=png "")  
  
为true  
后就break  
掉了，也就意味着这一路径不需要经过鉴权验证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSicsFLsmzvBcsbvku8wiblSkeTwzAjqp54gLtXHQ73sjibia5DRAXe0iaibD80707Ie4Y7XiaaqA7TOAcXg/640?wx_fmt=png "")  
  
对于漏洞的修复也是比较简单，直接进行一层url  
解码。  
  
对于..  
和%2e  
的绕过方式如下：  
  
/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp  
  
采用unicode uri  
替代原本的utf-8  
，即..=>%u002e  
来完成绕过。  
  
openfire  
采用内置的Jetty  
作为Web  
服务器，带着%u002e  
的uri  
进入Jetty  
，Jetty  
支持对此类unicode uri  
的解析，因此转为..  
，成功绕过访问到log.jsp  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSicsFLsmzvBcsbvku8wiblSk3Mo6ucO7HTQLpOWqlMWq680qgYCm4frkicvtSCel9cwicWkC6Qg7CXlQ/640?wx_fmt=png "")  
  
  
**#****02****‍**  
  
  
**同类漏洞**  
  
  
从官方的修复角度来看其实能找到类似的漏洞，官方的修复历程为：  
  
CVE-2008-6508  
  
Poc:  
  
/setup/setup-/../../log.jsp  
  
随后官方就修复了..  
绕过鉴权，通过添加一层验证，也就是后来被绕过的testURLPassesExclude  
来对传入的url  
验证是否含有..  
：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSicsFLsmzvBcsbvku8wiblSk9psoaOCS8t2zxdLceCYx5HcFSPNecCONM7wPbUfUGd7RviaC9aic9FVw/640?wx_fmt=png "")  
  
与此同时也将通配符这一特性加入鉴权机制中：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSicsFLsmzvBcsbvku8wiblSkne01WmYAsqlD9BgBTK8HRKTIlDxAln1ibSEezxtJku5qd3m8gY1OJcw/640?wx_fmt=png "")  
  
之后官方又添加了对应%2e  
的验证，然后就出现了现在最新的%u002e  
的绕过方案，与之类似的还有Eclipse Jetty  
。  
  
在CVE-2021-28164  
中可以使用：  
  
/%2e/WEB-INF/web.xml  
  
来读取web.xml  
，官方在修复后同样的被绕过的，貌似是分析官方修复补丁时捡漏的一处漏洞，也是采用unicode uri  
的方式bypass  
：  
  
/%u002e/WEB-INF/web.xml  
  
而在路径放行上，即配置文件中对于setup  
路径或者是静态文件放行，类似于weblogic console  
权限绕过，weblogic  
与openfire  
类似的，在配置文件中写了鉴权机制，对于css  
，images  
等都不需要鉴权，也同样导致了权限绕过。  
  
/console/css/%252e%252e%252fconsole.portal  
  
  
**#****03****‍**  
  
  
**修复**  
  
  
那么官方给出的修复建议有如下：  
  
1.  
严格限制访问网络  
  
2.  
修改配置文件  
```
```  
  
3.  
修改openfire.xml  
使控制台仅回环地址访问  
```
```  
  
4.  
使用AuthFilterSanitizer  
插件  
  
  
**#****04****‍**  
  
  
**reference**  
  
  
[1] Administration Console authentication bypass  
  
https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm  
  
[2] (CVE-2021-28164/CVE-2021-34429)Eclipse Jetty WEB-INF  
敏感信息泄露漏洞分析  
  
https://blog.csdn.net/weixin_50464560/article/details/120608463  
  
  
         
  
