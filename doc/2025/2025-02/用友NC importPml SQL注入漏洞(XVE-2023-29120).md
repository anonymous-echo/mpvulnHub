#  用友NC importPml SQL注入漏洞(XVE-2023-29120)   
Superhero  nday POC   2025-02-21 02:56  
  
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
  
  
用友NC是由用友公司开发的一套面向大型企业和集团型企业的管理软件产品系列。这一系列产品基于全球最新的互联网技术、云计算技术和 移动应用技术，旨在帮助企业创新管理模式、引领商业变革。  
**01******  
  
**漏洞概述**  
  
  
用友NC importPml接口存在SQL注入漏洞，攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
icon_hash="1085941792" && body="/logo/images/logo.gif"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLjyrpiaa6A0Vh3ebSDK2Td3TL4wpmOcKzXhiardIekSQJH77pXiaK9qhYYhZjT8ItXPxVwsIUic9g8rA/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
延时4秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLjyrpiaa6A0Vh3ebSDK2Td3JvUABrBVFN9HhjypnQiaWLQ4YliboK0iaLKhqTCVicKuYa9KClcAjeI9Aw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLjyrpiaa6A0Vh3ebSDK2Td3DzUndLiaHPgP0ibvnYLbpmYiaxCxUuRQ41NynXFvfttH3BVicmyDr6hXmQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLjyrpiaa6A0Vh3ebSDK2Td3VN9oTVzaPRvjOxwlElkzGiaAJk5kVKVTHrotcvrBjOGc88wEYFepdQQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLjyrpiaa6A0Vh3ebSDK2Td3N7tHaLRwO7evp39PKpKG15S2ScHx6xeMrPaYcprUaYP1H6KiasbSDLQ/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
厂商已发布漏洞修复程序，请前往以下地址下载：  
  
https://security.yonyou.com/#/noticeInfo?id=524  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新7-10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
