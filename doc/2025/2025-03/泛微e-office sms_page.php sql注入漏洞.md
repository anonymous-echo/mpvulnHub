#  泛微e-office sms_page.php sql注入漏洞   
Superhero  Nday Poc   2025-03-26 20:56  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号Nday Poc及作者不为此承担任何责任，一旦造成后果请自行承担！  
  
  
**00******  
  
**产品简介**  
  
  
泛微E-office是一款高效的企业协同办公平台，致力于提升组织内部的沟通与协作效率。它集成了流程审批、文档管理、任务分配、即时通讯等功能，支持多终端操作，帮助企业实现无纸化办公和智能化管理。通过灵活的模块化设计，E-office能够根据企业需求进行个性化定制，助力企业优化工作流程、提升整体运营效率。  
**01******  
  
**漏洞概述**  
  
  
泛微e-office sms_page.php接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 此漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
((header="general/login/index.php" || body="/general/login/view//images/updateLoad.gif" || (body="szFeatures" && body="eoffice") || header="Server: eOffice") && body!="Server:    couchdb") || banner="general/login/index.php"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJRjgQ1Rl0pGvHnEiauvkT29wzqhncsZCD2bibg6abPJTJS3PgoU8NJam3SRCl2IMkC0Wev86RcRIFQ/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
123123的MD5值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJRjgQ1Rl0pGvHnEiauvkT29ES8RlvEswoWUmZCj4IA4ZaPV7kZZLHgOzgBAlflAKvvIxMJe4BfhmA/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJRjgQ1Rl0pGvHnEiauvkT29iagQdu2Td09L3NcjPOrJv3l1XhfLK9gQZCBMvFAicT6lbPY8rpeoc8ibA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJRjgQ1Rl0pGvHnEiauvkT29yZzDDeIXyogIaXWUEjGcbaIpNYGLpYbBMgJAD68iaYISwnZHiaREd2dQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJRjgQ1Rl0pGvHnEiauvkT29Jy2JtrtfWDicQPC1MxIMGYTv8NymNAiayFrhOKmHS2y3Fib8OPcvLYokA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJRjgQ1Rl0pGvHnEiauvkT29JQK3NlUNsvlXfqKJ0RmdoSYLUIxqZUfF5PriaYWxnebkI9mqetQfSnQ/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
关注厂商官网动态，及时更新补丁信息。  
  
  
**06******  
  
**内部圈子介绍**  
  
  
【Nday漏洞实战圈】🛠️   
  
专注公开1day/Nday漏洞复现  
 · 工具链适配支持  
  
 ✧━━━━━━━━━━━━━━━━✧   
  
🔍 资源内容  
  
 ▫️ 整合全网公开Nday漏洞POC详情  
  
 ▫️ 适配Xray/Afrog/Nuclei检测脚本  
  
 ▫️ 支持内置与自定义POC目录混合扫描   
  
🔄 更新计划   
  
▫️ 每周新增7-10个实用POC（来源公开平台）   
  
▫️ 所有脚本经过基础测试，降低调试成本   
  
🎯 适用场景   
  
▫️ 企业漏洞自查 ▫️ 渗透测试 ▫️ 红蓝对抗   
▫️ 安全运维  
  
✧━━━━━━━━━━━━━━━━✧   
  
⚠️ 声明：仅限合法授权测试，严禁违规使用！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0beBCCyKGykkAazuPyvibgC0ooBGy9elQQ72f1WIB73UDYuPhx8cnCobvnOBdTcxmdwBbt2eAYIQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
