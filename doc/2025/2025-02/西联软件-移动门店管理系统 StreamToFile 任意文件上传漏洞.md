#  西联软件-移动门店管理系统 StreamToFile 任意文件上传漏洞   
Superhero  nday POC   2025-02-08 03:03  
  
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
  
  
西联软件旗下的移动门店管理系统  
是一款针对实体零售连锁门店设计的管理工具，系统涵盖了基本的销售、库存管理和报表统计等功能，能够满足门店日常运营的基本需求。此外，系统还支持多店铺的统一管理和协同运营，帮助企业实现资源的优化配置和高效利用。适用于各种类型的实体零售连锁门店，如超市、便利店、专卖店等。通过该系统，企业可以实现对门店运营的全面监控和管理，包括商品库存管理、销售数据分析、员工绩效管理等。同时，系统还支持多种结账方式和支付手段，提升了顾客的购物体验和满意度。  
**01******  
  
**漏洞概述**  
  
  
西联软件-移动门店管理系统 StreamToFile 接口存在文件上传漏洞，未经身份攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="西联软件提供云计算服务"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkLttUL8ejicfPV7nmxicYTmWIbPHSib3icDEWt6OHl1c3UXEARMJW47ALgh5fmOibdibjm6GzO2h9Xmicw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkLttUL8ejicfPV7nmxicYTmHGtb1M6ZbVoYrbK9WuauHiaaxrtdFDCKnkf1baBhPqShicVIVYaDGFxg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkLttUL8ejicfPV7nmxicYTmFknYfvDs8eXH85ica5Gat6uyQLusH6FTChxicak60C1CJlrdpTjHRgYQ/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkLttUL8ejicfPV7nmxicYTmdOmRf1m9c6apgicnIbQUoS9ibByFMSibIFA0ZhcYhpeBwOcuIyAqWhttw/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkLttUL8ejicfPV7nmxicYTm2cspUYiafhviaIEOEbx1IkSvKUAECWLOCtjMV0IZlHT1T4WTmk2k8xUA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkLttUL8ejicfPV7nmxicYTmzKsGfVsBuh8zFL0hmACss5g1PgUxuC2GAibia8N5vpxicnSYTngYra13Q/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
