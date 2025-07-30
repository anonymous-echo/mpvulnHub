#  Sierra:21 漏洞影响关键基础设施路由器   
Bill Toulas  代码卫士   2023-12-07 17:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Forescout 公司的Vedere Labs 发现，Sierra OT/IoT 路由器受21个新漏洞影响，它们威胁关键的基础设施，可导致远程代码执行、越权访问、XSS、认证绕过和拒绝服务攻击等。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSPcwrmiaKicicBnDibg7lsv2uqtoR3NTicYpsP52Ptk0CzUfLO24ek0pD3mP3t1zuYMAJ0fbMOP7B4Thw/640?wx_fmt=gif&from=appmsg "")  
  
  
这些漏洞影响 Sierra Wireless AirLink 蜂窝路由器和开源组件如 TinyXML 和 OpenNDS（开放的 Network Demarcation Service）。因高性能的 3G/4G/5G 和 WiFi 和多网络连接，AirLink 路由器在工业和任务关键应用程序的领域广受好评。  
  
复杂场景中使用多种模型如传输系统中的乘客 WiFi、紧急服务的车辆连接性、现场操作的长距离千兆位连接以及多种其它性能密集的任务。Forescout 公司表示，Sierra 路由器用于政府系统、紧急服务、能源、运输、水和废水设施、制造行业和医疗组织机构。  
  
  
**0****1**  
  
**漏洞及其影响**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSPcwrmiaKicicBnDibg7lsv2uqU7ly7pUDJ6zmhH7ibyOtPfhoWibxtlTic1Y6CCDK3XplWTk79REWYgiaKw/640?wx_fmt=gif&from=appmsg "")  
  
  
  
研究人员在 Sierra AireLink 蜂窝路由器、TinyXML 和 OpenNDS 组件中发现了21个新漏洞，而这些组件也是其它产品的一部分。在这些漏洞中，仅有1个是严重级别、8个是高危级别以及12个是中危级别。  
  
其中最值得注意的漏洞如下：  
  
- CVE-2023-41101（OpenNDS 中的RCE漏洞—严重级别，评分9.6）   
  
- CVE-2023-38316（OpenNDS 中的RCE漏洞—高危级别，评分8.8）  
  
- CVE-2023-40463（ALEOS 中的越权访问漏洞—高危级别，评分8.1）  
  
- CVE-2023-40464（ALEOS 中的越权访问漏洞—高危级别，评分8.1）   
  
- CVE-2023-40461（ACEmanager 中的XSS漏洞—高危级别，评分8.1）  
  
- CVE-2023-40458（ACEmanager 中的DoS 漏洞—高危级别，评分7.5）  
  
- CVE-2023-40459（ACEmanager 中的DoS 漏洞—高危级别，评分7.5）  
  
- CVE-2023-40462（与TinyXML 有关的 ACEmanager 中的 DoS 漏洞—高危级别，评分7.5）  
  
- CVE-2023-40460（ACEmanager 中的XSS漏洞—高危级别，评分7.1）  
  
  
  
在这些漏洞中，其中至少有五个漏洞无需攻击者认证即可遭利用。对于影响 OpenNDS 的其它漏洞而言，可能不需要进行认证，因为常用的攻击场景涉及客户端连接到网络或服务。  
  
研究人员表示，攻击者可利用其中一些漏洞“完全控制关键基础中的OT/IoT 路由器”。路由器受陷可导致网络中断、间谍活动或者横向移动到更加重要的资产和恶意软件部署。研究人员解释称，“除了人类攻击者外，这些漏洞也可被僵尸网络用于自动传播、与C2 服务器进行通信以及执行DoS 攻击活动”。  
  
安全研究员在 Shodan 搜索运行扫描联网设备时，发现超过8.6万台 AirLink 路由器被暴露，涉及多种行业的关键组织机构如电力调配、车辆追踪、废物管理以及国家医疗服务。大约80%的被暴露系统位于美国，其次是加拿大、澳大利亚、法国和泰国。其中，仅有不到8600台路由器部署了在2019年所披露漏洞的补丁，而因使用默认的 SSL 证书导致超过2.2万台路由器易受中间人攻击。  
  
  
**0****2**  
  
**修复建议**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSPcwrmiaKicicBnDibg7lsv2uqU7ly7pUDJ6zmhH7ibyOtPfhoWibxtlTic1Y6CCDK3XplWTk79REWYgiaKw/640?wx_fmt=gif&from=appmsg "")  
  
  
  
建议管理员升级到修复了所有漏洞的 ALEOS 版本4.17.0，或者至少升级至 ALEOS 4.9.9。后一个版本中包含除了 OpenDNS  强制认证门户以外的修复方案，而该门户在公开互联网和局域网之间设置了障碍。  
  
OpenDNS 项目也在 10.1.3版本为影响开源项目的漏洞发布了安全更新。  
  
因目前 TinyXML 已被弃用，因此影响该项目的CVE-2023-40462漏洞没有修复方案。  
  
Forescout 公司还建议采取如下措施，增强防护能力：  
  
1、更改 Sierra Wireless 路由器和类似设备中的默认 SSL 证书。  
  
2、禁用或限制非关键服务如强制认证门户、Telnet和SSH。  
  
3、执行 web 应用防火墙，保护 OT/IoT 路由器免受 web 漏洞影响。  
  
4、安装 OT/IoT 软件IDS，监控外部和内部网络流量中的安全事件。  
  
Forescout 公司发布技术报告解释了这些漏洞及其利用条件。该公司表示，威胁行动者不断攻击路由器和网络基础设施环境，通过使用自定义恶意软件发动攻击，利用这些设备实现持久性和监控目的。网络犯罪分子一般通过这些路由器代理恶意流量或者扩大其僵尸网络的体量。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[僵尸网络利用路由器和NVR中的0day 发动大规模DDoS攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518215&idx=2&sn=0cb6a4efc122aea60b37aa4e6844a905&chksm=ea94b96ddde3307b862463c3e5a6894fd412bcf008537b966f28e1f2381489d19c1055bc4211&scene=21#wechat_redirect)  
  
  
[ConnectedIO 路由器中存在多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517824&idx=2&sn=caafc74a2a9253eb8423616f3d2556fe&chksm=ea94b7eadde33efc78c5538244f09266b3ea1a6933ac0758664b28714bbf73f252bbf7eda9b2&scene=21#wechat_redirect)  
  
  
[华硕路由器易遭多个RCE漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517570&idx=1&sn=34fd77e3506951e7f7fd62a7ab442b2c&chksm=ea94b4e8dde33dfe4882db94eae6cfe3f510868509c9e72ccc806d2d65d5c5faaea9897b5af3&scene=21#wechat_redirect)  
  
  
[Milesight 工业路由器受数十个RCE漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517324&idx=2&sn=148eb4867662d131943cf25c80175992&chksm=ea94b5e6dde33cf0d8a2d47cf997596fef2f4a4cce32ddcc3df68065796ee8ad4be5dc6c9d66&scene=21#wechat_redirect)  
  
  
[华硕紧急修复多个严重的路由器漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516769&idx=1&sn=e00e30e1c0b1187da247a4f936d2761e&chksm=ea94b30bdde33a1d1e665e5aff83de4c7dc1f514f22b2f801b2394245122fa4c1d765b8d7585&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/atlassian-patches-critical-rce-flaws-across-multiple-products/  
  
  
题图：  
Pixabay  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
