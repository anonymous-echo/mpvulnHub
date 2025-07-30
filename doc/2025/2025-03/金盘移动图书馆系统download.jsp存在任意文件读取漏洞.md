#  金盘移动图书馆系统download.jsp存在任意文件读取漏洞   
Superhero  Nday Poc   2025-03-08 17:19  
  
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
  
  
金盘移动图书馆管理系统是集掌上门户，掌上APP，微信平台为一体的移动服务解决方案，在移动智能时代拉近读者与图书馆之间的距离。其存在信息泄露漏洞，泄露管理员账号密码等敏感信息。  
**01******  
  
**漏洞概述**  
  
  
金盘移动图书馆系统download.jsp接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取服务器任意文件，从而获取大量敏感信息。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
app="金盘软件-金盘移动图书馆系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLcyxr8sf0RmTjrdOGC5SnXwGqcibaBVMFZJuwU2joNubIOTwe7mTX4DW5SFH0KOw7GosOCicmo0rUg/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLcyxr8sf0RmTjrdOGC5SnXFY2DIXSDTAN7bSyR6B61yKpK6xHEuIicib1JYFUngTYBDU4UVow8hkog/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLcyxr8sf0RmTjrdOGC5SnXU6sAl26iaiaATJWrOWd8Nrg6gGKyznvk8RQIRNv2NqRSibSgJbLibYnsHQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLcyxr8sf0RmTjrdOGC5SnX9L9LRJEABsSp0JKD5L2CFKxZMpv9qox6UNHsajXO355RpWDFA1bcTw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLcyxr8sf0RmTjrdOGC5SnXA9tCYgVxSczeicuqZQsmkX3agTkkhb3ic4r4kraNfdhqv8kkty6MlOlg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新7-10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
