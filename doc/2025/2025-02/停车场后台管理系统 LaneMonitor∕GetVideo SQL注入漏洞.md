#  停车场后台管理系统 LaneMonitor/GetVideo SQL注入漏洞   
Superhero  Nday Poc   2025-02-19 10:10  
  
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
  
  
停车场后台管理系统  
是一种专为停车场管理者设计的综合管理平台，旨在提供全面、高效、智能的停车场运营管理解决方案，系统利用现代信息技术，如物联网、大数据、云计算等，实现对停车场内车辆进出、车位管理、费用结算、安全监控等各个环节的自动化、智能化管理。该系统能够显著提升停车场的管理效率，降低运营成本，并为车主提供更加便捷、舒适的停车体验。  
**01******  
  
**漏洞概述**  
  
  
停车场后台管理系统 LaneMonitor/GetVideo 存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
icon_hash="938984120"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKaho6ftLuCzOn8X25ZDKscRbfWKgup27kSCzmHc5mJzia7AjvVNNbIsmR8Kib2kScicSYJ3ibviaPambw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKaho6ftLuCzOn8X25ZDKscJvOrGuEmglNLwU1RI0ibx2HvGdvt9KBvM8dGbGKP4u2Wl6ebyAcfDiaA/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKaho6ftLuCzOn8X25ZDKscWnN1zajgv6GmbFMIbASH9wHia2f1gH5hZP2ZltHZUX4V5vIQMX1tIKg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKaho6ftLuCzOn8X25ZDKscUibKhBq23D4XtMIFMQJKoyOcibSZERYuOzPP1LSJl5rGTDvX7bNohA5g/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKaho6ftLuCzOn8X25ZDKscaoKDmEZrDxv9I4TPGf5aicIlVbUiasEyG6J5Olt1icZDicicJndqhK2480A/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKaho6ftLuCzOn8X25ZDKscZfP7Gwoib8m1ic324sudrJcxDVu5s9uAV48BGpR4ldoLsficJq1WAlmbw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、打上对应补丁  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新7-10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
