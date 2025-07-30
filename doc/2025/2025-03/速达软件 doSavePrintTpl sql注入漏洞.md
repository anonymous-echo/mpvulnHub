#  速达软件 doSavePrintTpl sql注入漏洞   
Superhero  Nday Poc   2025-03-22 15:59  
  
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
  
  
速达软件是中国知名的中小企业管理软件服务商，成立于1999年，总部位于广州，专注于为中小微企业提供一站式数字化解决方案。其核心产品涵盖财务管理系统、供应链管理、生产制造执行(MES)、客户关系管理(CRM)等模块，支持云端SaaS部署与本地化安装双模式，兼容Windows、Linux系统及移动端应用。软件采用B/S架构设计，集成进销存、财务核算、报表分析等核心功能，支持多仓库管理、智能批次跟踪、税务一键申报等场景化需求，并与电子发票、银企直连等第三方系统无缝对接。凭借低代码开发平台和模块化设计，企业可快速实现业务流程定制化，满足商贸流通、生产制造、连锁零售等行业的数字化转型需求。速达软件以操作简便、性价比高著称，累计服务超百万家企业，提供从数据迁移、系统培训到售后运维的全周期支持，并通过ISO认证及国家高新技术企业资质，持续推动企业管理智能化升级。  
**01******  
  
**漏洞概述**  
  
  
速达软件 doSavePrintTpl接口处存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="速达软件技术"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJdq5hgmO93A0AUkuCuyfRRf12tyNjuaoiaHaSwqueiaagIddKhR9aaR1t213c5s8JgRDdUpL259ySQ/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
延时4秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJdq5hgmO93A0AUkuCuyfRRH2uicKmcVwIJGaz8LJe66icUuMLZSgIlMs0wcmfpUWJIFRVJXE2thMbQ/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJdq5hgmO93A0AUkuCuyfRRweeyNyZxR0naPgmwWzYXttSNJ5Nzg1XTc4XSoWRJu5ibtro9pLHpmTA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJdq5hgmO93A0AUkuCuyfRRHwpmYVibdrNdEBD0HI8HsDYlPEM7uiafQK3kQbRforzF8hGEsyw4g99Q/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJdq5hgmO93A0AUkuCuyfRRV6J9kGYNAH7mNiaUlEGDxdd8yibarcaKGbX2JnlXlfNBVo1JkENopY9g/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
关注厂商官网动态，及时更新补丁信息。  
  
  
**06******  
  
**内部圈子介绍**  
  
  
【Nday漏洞实战圈】🛠️   
  
专注公开漏洞复现 · 工具链适配支持  
  
 ✧━━━━━━━━━━━━━━━━✧   
  
🔍 资源内容  
  
 ▫️ 整合全网公开Nday漏洞POC详情  
  
 ▫️ 适配Xray/Afrog/Nuclei检测脚本  
  
 ▫️ 支持内置与自定义POC目录混合扫描   
  
🔄 更新计划   
  
▫️ 每周新增7-10个实用POC（来源公开平台）   
  
▫️ 所有脚本经过基础测试，降低调试成本   
  
🎯 适用场景   
  
▫️ 企业漏洞自查 ▫️ 授权渗透测试 ▫️ 工具链调试   
  
✧━━━━━━━━━━━━━━━━✧   
  
⚠️ 声明：仅限合法授权测试，严禁违规使用！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLT7IMzAPs3jMFqkApVcvKf84FHzvZkkXajucZnFfZ1rxv1nLOJBNksF6MuVxDVl5jJLKWHq58xsw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
