#  用友NC checkekey SQL 注入漏洞(XVE-2024-37013)   
Superhero  nday POC   2025-02-18 03:15  
  
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
  
  
用友  
NC（也称用友NC6或NCC）是用友网络科技股份有限公司开发的一款企业级管理软件，旨在为企业提供全方位的管理服务。主要面向大型企业和集团公司，提供全面的财务和业务管理解决方案，助力企业实现数字化转型和高效管理。采用J2EE架构和先进开放的集团级开发平台UAP，融合了云计算技术、移动应用技术等最新互联网技术，形成了集团管控8大领域15大行业68个细分行业的解决方案。凭借其全面的功能、强大的集成能力和高度的可定制化，成为许多大型企业和集团公司进行财务和业务管理的首选工具。  
**01******  
  
**漏洞概述**  
  
  
用友NC中checkekey存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码,站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
app="用友-UFIDA-NC"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZMmgbfFH5cEDtnffWFZib1jFaz96SkGYdKs912Xq1Qawl8FTRmhQlKBzgaEJEUWnnSA03UXrgNMg/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZMmgbfFH5cEDtnffWFZib1uJHMvPyzAqllBpSaRxdcibV3uZRia9hibXBYAGhCibJAzge0qxdiaI8Azkw/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZMmgbfFH5cEDtnffWFZib1U8Miaib4MmL8u4mo2GTIsEcwsAS9tsMLhK39Ax6SDCTOXOPVPzZGo0tA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZMmgbfFH5cEDtnffWFZib1Oq4m41OO1mNj06fcmg6lkeTicAahUVvtwQeVVTpfXLjibJARic6g5khrw/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZMmgbfFH5cEDtnffWFZib1QFn6o1A86KFgrjKh4IATDoAk1csJWfNYRnXjP4enn1hItSkFvLibNoA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIZMmgbfFH5cEDtnffWFZib1cGUazs4vrBSd7q7kwOBNmaqXmYTqpI4TnTyPibo85tTE8z7jY9iaE2gA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
