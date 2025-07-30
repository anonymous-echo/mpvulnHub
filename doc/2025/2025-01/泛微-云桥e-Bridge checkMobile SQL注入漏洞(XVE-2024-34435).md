#  泛微-云桥e-Bridge checkMobile SQL注入漏洞(XVE-2024-34435)   
Superhero  nday POC   2025-01-20 09:16  
  
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
  
  
泛微云桥e-Bridge是在“互联网+”"的背景下研发的一款用于桥接互联网开放资源与企业信息化系统的系统集成平台。它旨在解决企业信息化建设中面临的系统对接复杂、信息孤岛等问题，通过提供高效、便捷的系统集成解决方案，帮助企业实现业务流程的优化和升级。该产品支持将企业内部系统的消息推送到用户的移动设备上，使得用户能够随时随地接收和处理工作信息，提高了工作的及时性和响应速度。  
**01******  
  
**漏洞概述**  
  
  
泛微-云桥e-Bridge checkMobile 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
app="泛微云桥e-Bridge"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwINFdoTG52pcG2xtScxiaibh4I7rRq0yHgVhWctXGf52bH3O1bZaHiaYGv7hPcFda9iaJbQq6PaRVWIFA/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
延时8秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJIaByIxKeq10RG3zNBia9rGsN50cv6QtWNysicb1hOCx2j8LSg0IkTvxOovU0AzYOWv12VuABUqw6A/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJIaByIxKeq10RG3zNBia9rGQMUIH4ZK9MqfPnrYyjYtrxsV7QPgqBRelbPf5yClzj50j64UUwE6AA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJIaByIxKeq10RG3zNBia9rGXmXdwYSabicu6GBM7qmA6RxgeHKZoelKFR1ibwYaeY08OeibNv8YouFPg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJIaByIxKeq10RG3zNBia9rG0lv031ZKDW6HUicNibFYVnaPdRZYCLPw2rDr7ibCib38crFBxniaKjYc1yw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJIaByIxKeq10RG3zNBia9rGlIF7SemfM1mkydB5l4S34AP4HBIxibFbvvH30eYTgCoEkMBkQ89X5Xw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
目前官方已发布安全补丁，建议受影响用户尽快升级至安全版本  
  
https://www.weaver.com.cn/  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
