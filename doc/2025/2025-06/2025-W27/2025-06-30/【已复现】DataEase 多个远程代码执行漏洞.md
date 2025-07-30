> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0ODM3NTU5MA==&mid=2247494128&idx=2&sn=84fbc29915f49915f2acbdee7c978011

#  【已复现】DataEase 多个远程代码执行漏洞  
原创 360漏洞研究院  360漏洞研究院   2025-06-30 11:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5nNKGRl7pFgbJxnOxcKdRicA5Vlgv8VdjNEa8tGFyzVgC6Q6dlYR7JSnqNf6hodTZqXAibl0ZqFHlNgZKH8hT2jQ/640?wx_fmt=gif&from=appmsg "")  
  
  
<table><tbody><tr style="box-sizing: border-box;"><td colspan="4" data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;background-color: rgb(100, 130, 228);box-sizing: border-box;padding: 0px;"><section style="text-align: center;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞概述</span></strong></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞名称</span></strong></p></section></td><td colspan="3" data-colwidth="75.0000%" width="75.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">DataEase远程代码执行</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞编号</span></strong></p></section></td><td colspan="3" data-colwidth="75.0000%" width="75.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">CVE-2025-53004</span></p><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">CVE-2025-53005</span></p><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">CVE-2025-53006</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">公开时间</span></strong></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">2025-6-30</span></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span style="color: rgb(0, 0, 0);box-sizing: border-box;"><span leaf="">CVSS 3.1</span></span></strong></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">9.1</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞类型</span></strong></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">代码执行</span></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">POC状态</span></strong></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">已公开</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span style="color: rgb(0, 0, 0);box-sizing: border-box;"><span leaf="">利用可能性</span></span></strong></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">高</span></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span style="color: rgb(0, 0, 0);box-sizing: border-box;"><span leaf="">EXP状态</span></span></strong></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">已公开</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">在野利用状态</span></strong></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">未发现</span></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">技术细节状态</span></strong></p></section></td><td data-colwidth="25.0000%" width="25.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">已公开</span></p></section></td></tr></tbody></table>  
  
  
**01**  
  
影响组件  
  
  
  
**DataEase**  
 是一款开源的数据可视化分析工具，旨在帮助用户快速分析数据、洞察业务趋势，并通过提供丰富的数据可视化和分析功能，协助用户轻松地进行数据探索和决策支持。  
  
  
DataEase支持多种数据源连接，包括MySQL、PostgreSQL、Oracle、SQL Server、Redshift等，通过JDBC技术实现与各类数据库的连接和交互。  
  
  
JDBC（Java Database Connectivity）驱动程序提供了Java应用程序与数据库之间的标准接口，是Java生态系统中连接数据库的重要组件。  
  
  
**02**  
  
**漏洞描述**  
  
  
  
近日，DataEase发布安全更新修复了多个高危漏洞(**CVE-2025-53004**  
，**CVE-2025-53005**  
，**CVE-2025-53006**  
)，该漏洞与JDBC URL的处理机制有关，拥有后台权限的攻击者可通过精心构造的连接参数**执行任意代码**  
，从而获取服务器权限。  
  
  
**03**  
  
**漏洞复现******  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5nNKGRl7pFhgP2RRUSMhqLSLU9Ctuzia19wKZVqfEKFIIsh0JvdqVjGD4CrnKTLWVqwUBTg8j16tkVkTCUQ2ckQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5nNKGRl7pFhgP2RRUSMhqLSLU9Ctuzia1hJiaKjY4zFFgxIAVCUg4RlkrSMzKBH10lR4rHsVCKyDGYwqicj477OvQ/640?wx_fmt=png&from=appmsg "")  
  
CVE-2025-53004  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5nNKGRl7pFhgP2RRUSMhqLSLU9Ctuzia1ickoWL19VZpsEdKbia6ouG0SZ5bMchicKCmDssib7fdANh2w6F3wrSlpyQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5nNKGRl7pFhgP2RRUSMhqLSLU9Ctuzia1EmhdqnZwD5jUENF3ewJMj4DYFmmzISRAVibYloJbNQxlGialaEjsP5HA/640?wx_fmt=png&from=appmsg "")  
  
CVE-2025-53005  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5nNKGRl7pFhgP2RRUSMhqLSLU9Ctuzia1eBic4j2SoB98HFrrV9efj3T8QMAvXgxvWqu6b9JTedicEeEjazicL2l5Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5nNKGRl7pFhgP2RRUSMhqLSLU9Ctuzia16V4Gt3VTB4K4mutc2LY3kyRtwaZIXVTaq2Py4wDticFZ5xcd8ib5LzIQ/640?wx_fmt=png&from=appmsg "")  
  
CVE-2025-53006  
  
  
**04**  
  
**漏洞影响范围******  
  
  
  
DataEase < 2.10.11  
  
  
**05**  
  
**修复建议******  
  
  
  
**正式防护方案**  
  
针对此安全漏洞，官方已经发布了漏洞修复版本，请立即更新到安全版本：  
  
DataEase >= 2.10.11  
  
下载链接：  
  
https://dataease.cn  
  
https://github.com/dataease/dataease/releases/tag/v2.10.11  
  
安装前，请确保备份所有关键数据，并按照官方指南进行操作。安装后，进行全面测试以验证漏洞已被彻底修复，并确保系统其他功能正常运行。  
  
  
**临时缓解措施**  
  
1.该漏洞需要攻击者拥有后台访问权限，请做好相关账号密码访问控制，杜绝弱口令。  
  
2.该漏洞利用需要服务器连接攻击者控制的外网主机，限制服务器对外网的访问权限可一定程度缓解漏洞后续利用。  
  
  
**06**  
  
**时间线**  
  
  
  
2025年6月30日，360漏洞研究院发布安全风险通告。  
  
  
**07**  
  
参考链接  
  
  
  
https://github.com/dataease/dataease/security/advisories/GHSA-mfg2-qr5c-99pp  
  
https://github.com/dataease/dataease/security/advisories/GHSA-q726-5pr9-x7gm  
  
https://github.com/dataease/dataease/security/advisories/GHSA-99c4-h4fq-r23v  
  
  
**08**  
  
更多漏洞情报  
  
  
  
建议您订阅360数字安全-漏洞情报服务，获取更多漏洞情报详情以及处置建议，让您的企业远离漏洞威胁。  
  
  
邮箱：360VRI@360.cn  
  
网址：https://vi.loudongyun.360.net  
  
  
  
“洞”悉网络威胁，守护数字安全  
  
  
**关于我们**  
  
  
360 漏洞研究院，隶属于360数字安全集团。其成员常年入选谷歌、微软、华为等厂商的安全精英排行榜, 并获得谷歌、微软、苹果史上最高漏洞奖励。研究院是中国首个荣膺Pwnie Awards“史诗级成就奖”，并获得多个Pwnie Awards提名的组织。累计发现并协助修复谷歌、苹果、微软、华为、高通等全球顶级厂商CVE漏洞3000多个，收获诸多官方公开致谢。研究院也屡次受邀在BlackHat，Usenix Security，Defcon等极具影响力的工业安全峰会和顶级学术会议上分享研究成果，并多次斩获信创挑战赛、天府杯等顶级黑客大赛总冠军和单项冠军。研究院将凭借其在漏洞挖掘和安全攻防方面的强大技术实力，帮助各大企业厂商不断完善系统安全，为数字安全保驾护航，筑造数字时代的安全堡垒。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5nNKGRl7pFgbJxnOxcKdRicA5Vlgv8Vdj79uMHokrh6ZZDyK49UF68xwvH2ttJ0eicYjADfDN3rsicht6B4toKg7w/640?wx_fmt=gif&from=appmsg "")  
  
  
