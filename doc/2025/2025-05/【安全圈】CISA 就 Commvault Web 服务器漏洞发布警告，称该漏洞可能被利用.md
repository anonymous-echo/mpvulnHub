#  【安全圈】CISA 就 Commvault Web 服务器漏洞发布警告，称该漏洞可能被利用   
 安全圈   2025-04-30 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaRYALoShbHCgQsHEMsnric9EPiaibjl6mSYGOEicO386BA8zUURjr7LicuEHtu9adib0o4y6ekUJakYPmg/640?wx_fmt=png&from=appmsg "")  
  
网络安全和基础设施安全局 (CISA) 已将  
Commvault Web 服务器  
漏洞 (CVE-2025-3928) 添加到其已知被利用漏洞 (KEV) 目录中，这表明威胁行为者正在积极利用此安全漏洞。   
  
该机构于 2025 年 4 月 28 日宣布了这一补充，要求联邦机构在 2025 年 5 月 17 日之前根据具有约束力的操作指令 (BOD) 22-01 修复该漏洞。  
## Commvault Web 服务器未指定漏洞 – CVE-2025-3928   
  
CVE-2025-3928 被归类为影响 Commvault Web Server 的“未指定漏洞”，该漏洞使经过身份验证的远程攻击者能够在受感染的系统上创建和执行 Webshell。   
  
根据国家漏洞数据库，此高严重性漏洞的 CVSS 基本评分为 8.8，反映了其巨大潜在影响。  
  
CISA 引用的 Commvault 建议指出：“不良行为者可以通过创建和执行 webshell 来破坏 Web 服务器。”   
  
这种类型的攻击允许恶意行为者以 Web 服务器的权限执行任意命令，同时保持对受感染系统的持续访问。  
  
该漏洞的漏洞预测评分系统 (EPSS) 分数为 0.10%，表明未来 30 天内被主动利用的可能性。   
  
尽管这一比例相对较低，但 CISA 将该漏洞添加到 KEV 目录中，证实了漏洞利用已经发生。  
<table><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">风险因素</span></font></font></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">细节</span></font></font></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">受影响的产品</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">Commvault Web 服务器（Windows 和 Linux）最高版本：11.20.21611.28.14011.32.8811.36.45</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">影响</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">– 完全服务器入侵 – 执行 webshell – 机密数据泄露 – 服务中断 – 完整性修改</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">漏洞利用前提条件</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">远程、经过身份验证的低权限攻击者</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVSS 3.1 评分</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">8.8（高）</span></font></font></td></tr></tbody></table>  
**受影响的系统和修补版本**  
  
该安全漏洞影响 Windows 和 Linux 平台上的 Commvault Web Server 部署。Commvault 已在以下版本中修复此漏洞：  
- 11.36.46  
- 1989年11月32日  
- 11.28.141  
- 11.20.217  
运行该软件早期版本的组织仍然容易受到潜在攻击。  
  
CISA  
建议  
各组织在 5 月 17 日截止日期之前采取以下行动之一：  
- 根据供应商的说明采取缓解措施  
- 遵循适用的 BOD 22-01 云服务指南  
- 如果没有缓解措施，请停止使用该产品  
虽然 BOD 22-01 要求正式仅适用于联邦民事行政部门 (FCEB) 机构，但 CISA 强烈鼓励所有组织优先及时修复目录漏洞作为其安全实践的一部分。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】吉利APP、领克APP突然崩了！有车主在路边苦等3小时，最新回应](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069352&idx=1&sn=db684cad13f694beef16dd9d35410ac6&scene=21#wechat_redirect)  
  
  
  
[【安全圈】玛莎百货数据泄露与 Scattered Spider 勒索软件攻击有关](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069352&idx=2&sn=0cfbe9d83610f722e86d78f4f9ae4b37&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Akira 勒索软件攻击后，Hitachi Vantara 服务器下线](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069352&idx=3&sn=374251b21e2cc1eace0852a7ada06ad9&scene=21#wechat_redirect)  
  
  
  
[【安全圈】RansomHub勒索软件部署恶意软件以危害企业网络](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069352&idx=4&sn=6eab06942a72aa12743056453fa44f1d&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
