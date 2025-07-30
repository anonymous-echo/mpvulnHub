#  用友U8CRM biztype.php sql注入漏洞   
Superhero  Nday Poc   2025-03-30 15:32  
  
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
  
  
用友U8CRM是用友软件  
推出的一款面向中小企业的客户关系管理（CRM）系统，旨在帮助企业实现客户资源的有效管理和销售流程的优化。它集成了客户管理、销售管理、市场营销、服务管理等功能模块，支持企业从线索获取、商机跟进到合同签订的全流程管理。通过数据分析和业务流程自动化，U8CRM能够提升销售团队的工作效率，增强客户满意度，助力企业实现精准营销和业绩增长。其灵活的系统架构和与用友U8+ ERP的无缝集成，使其成为中小企业数字化转型的理想选择。  
**01******  
  
**漏洞概述**  
  
  
用友 U8 CRM客户关系管理系统 biztype.php 接口存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
title="用友U8CRM"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLRy1ic4KicT7UL4UloWpibOHY8JzHwbKe9l4lFlhuwDs1HAO4QhOMkG4Vtniaq6gWxEwLuK4j7SQ21rw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
延时8秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLRy1ic4KicT7UL4UloWpibOHYlhXicicOz32oEpsIM5ulY6cLsXYLlftd5b4th5goqs7mskLiamyiaJoLTw/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLRy1ic4KicT7UL4UloWpibOHYHhybJKZQXnfTZHTdlXyGlXVCwTLibYVQmUbH6t72Lfyqu8puYUz7FDw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLRy1ic4KicT7UL4UloWpibOHY8HR92ofUWFlVYRLFvHBu7WZibibPGL8MG3oULTJnWyqMc9dAY7xhGribA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLRy1ic4KicT7UL4UloWpibOHYiaAQQFKsLSv2Ae9w4A8Ms1yiakGnnteC5lclP2bXv8eeVf4IB6ohLChA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLRy1ic4KicT7UL4UloWpibOHY8dLATaY5Yia4GoqX0Qkpou4ydDArpMc0F6a1SqKQ4Vq9Dr827ics40QQ/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
下载官方补丁进行修复  
  
  
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
  
  
