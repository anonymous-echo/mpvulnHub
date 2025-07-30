#  友数聚 CPAS审计管理系统V4 downPlugs 任意文件读取漏洞   
Superhero  nday POC   2025-01-25 09:50  
  
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
  
  
友数聚CPAS审计管理系统V4是友数聚科技有限公司(用友集团成员企业)开发的一款审计软件产品，它是CPAS审计信息系统的一个重要组成部分。中国注册会计师协会于2012年与用友集团签订战略合作协议，合力开发了CPAS审计信息系统，以服务于本土会计师事务所，建立管理集中、覆盖全面、分工合作、反应及时的一体化审计信息系统。CPAS审计信息系统紧联用户使用习惯，紧扣业务应用需求，紧随行业发展趋势，已形成CPAS审计管理系统、CPAS审计作业系统、CPAS电子档案系统、CPAS合并系统和CPAS函证系统等五大系统互联互通、融合应用的审计信息化全流程应用平台，为大中型会计师事务所提供了一整套全流程审计信息化解决方案。  
**01******  
  
**漏洞概述**  
  
  
友数聚 CPAS审计管理系统V4 downPlugs 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="/cpasm4/static/cap/font/iconfont.css"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIG2qy9ErhJgKoRdcc8fnM6xh0sbZdEjmDVBQO2IrZR3luaGwvPiagfSibUNevNCPdibISW4UqJibIUcw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIG2qy9ErhJgKoRdcc8fnM6peJ0l3llV02MOtYETTn3UmXhr0WBSK99ZbKMSkflmIAGYZicD0Jyqfw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIG2qy9ErhJgKoRdcc8fnM65Vps9nWVz8ZInKodvaZMxZCxJxaaaNWaqhbQaicUH9nDNRbBFZYcsCw/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIG2qy9ErhJgKoRdcc8fnM6grQjtkSQadkUsRRJtMMdsjia8NlOC40pUUgmGm14vBgmgbaKPA4kDLQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIG2qy9ErhJgKoRdcc8fnM6K3n4XicmaOPIFuIkNEHwgk5YOSo1Bkyknl4gicCL1XjG1R7mXUMdAsibQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
