#  方正畅享全媒体新闻采编系统 imageProxy.do 任意文件读取漏洞   
Superhero  nday POC   2025-02-13 01:57  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
方正畅享全媒体新闻生产系统是以内容资产为核心的智能化融合媒体业务平台，融合了报、网、端、微、自媒体分发平台等全渠道内容该平台由协调指挥调度、数据资源聚合、融合生产、全渠道发布、智能传播分析、融合考核等多个平台组成，贯穿新闻生产策、采、编发、存、传、评、营的每个环节,涵盖桌面端、移动端(超融合掌上编辑部)、大屏端三端联动进行编采业务支撑。平台通过大数据+AI的赋能，助力融媒体在内容生产、数据资产、报道指挥、绩效考核等业务环节。  
**01******  
  
**漏洞概述**  
  
  
方正畅享全媒体新闻采编系统 imageProxy.do 接口存在任意文件读取  
漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
app="FOUNDER-全媒体采编系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIEaYbqUjNTRfDTUIbDVseIjdVcu5FxAGibiaGviaoYibqY6a9kicT9TzskHs8t4XDYMALQxkibVZvbJpHA/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIEaYbqUjNTRfDTUIbDVseIILFu5fYNibicaHjSB2EHoUnef8UbGZwNibju6ca9416Phub8MoXCdudng/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIEaYbqUjNTRfDTUIbDVseIw0icMZOicphVohLdpLGuWbXJbdg7gOr4A2NuYsiaWe04YFWuEiclZHkWOQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIEaYbqUjNTRfDTUIbDVseI0fFJap5ct6wwX1SjzOzFm2dpaEd7zBM8SrFXlbQeI9IoPcxoEr4wNQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIEaYbqUjNTRfDTUIbDVseIlcBGXFuib291BDtA2MYiboWWnm5e26M7ib1CDgudSwW5vNrr4KWNx7Wwg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新7-10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
