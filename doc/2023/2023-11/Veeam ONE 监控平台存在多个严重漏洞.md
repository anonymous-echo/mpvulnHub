#  Veeam ONE 监控平台存在多个严重漏洞   
Sergiu Gatlan  代码卫士   2023-11-07 16:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
  
**今天，Veeam 发布热补丁，修复了位于 Veeam ONE IT 基础设施监控和分析平台中的四个漏洞，其中两个是严重级别。**  
  
  
  
Veeam 公司对这两个严重漏洞的CVSS评分为9.8分，它们可导致攻击者获得远程代码执行权限并窃取易受攻击服务器中的NTLM哈希。余下两个漏洞是中危级别，要求用户交互或影响有限。  
  
Veeam 发布安全公告指出，“Veeam ONE 中的一个漏洞可导致未认证攻击者获得Veeam One 用于访问其配置数据库的 SQL 服务器连接信息，从而可能导致在托管 Veeam ONE 配置数据库的SQL 服务器上执行远程代码。”该漏洞的编号是CVE-2023-38547。  
  
Veeam 公司表示，第二个严重漏洞CVE-2023-38548 “可导致能访问 Veeam ONE Web Client 的非权限用户获得由 Veeam ONE Reporting Service 所使用的账户的 NTLM 哈希。”  
  
Veeam 还修复了CVE-2023-38549，可导致具有 Power User 角色的攻击者通过XSS攻击窃取管理员的访问令牌，不过执行XSS攻击要求用户与拥有 Veeam ONE Administrator 角色的人员进行交互。  
  
第四个漏洞CVE-2023-41723 可被具有只读权限用户角色的恶意人员访问 Dashboard Schedule（攻击者无法做出修改）。这些漏洞影响受活跃支持的 Veeam ONE 版本到最新版本。该公司已发布如下热修复方案：  
  
- Veeam ONE 12 P20230314 (12.0.1.2591)  
  
- Veeam ONE 11a (11.0.1.1880)  
  
- Veeam ONE 11 (11.0.0.1379)  
  
  
  
管理员必须阻止受影响服务器上的 Veeam ONE 监控和报告服务，用热修复方案中的文件替换磁盘上的文件，并重启服务部署这些热修复方案。  
  
3月，Veeam 还修复了位于 Backup & Replication 软件中的一个高危的 Backup Service 漏洞 (CVE-2023-27532)，它可被用于攻陷备份基础设施主机。该漏洞之后遭受经济利益驱动的 FIN7 组织的利用。该组织被指发动多起勒索攻击，如 REvil、Maze、Egregor 和 BlackBasta 等。几个月后，Cube 勒索团伙被指利用该漏洞攻击位于美国的关键基础设施以及拉美地区的IT公司。  
  
Veeam 公司表示，该软件的客户已超过45万且遍布全球，覆盖了82%的财富500强公司，72%的企业用户在全球2000年度排名之内。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Veeam修复严重漏洞，可攻陷备份基础设施](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515885&idx=3&sn=ffefe13a8f5da2c680df756b9e641cfd&chksm=ea948f87dde30691fda5efbd07f068606a775eb6e6e596b39f44c7f1cd843a4c64a24c1a88a7&scene=21#wechat_redirect)  
  
  
[Veeam 数据备份解决方案修复多个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510935&idx=2&sn=16d2e8be99d29f0ceb82b7596b370911&chksm=ea949afddde313ebf772d24347c8ee4aa98f2e78b2da9850b34569457f918e386175b6d5b85a&scene=21#wechat_redirect)  
  
  
[瑞士数据管理公司 Veeam 泄露4.45亿条客户记录](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488036&idx=3&sn=d07a6878bd7689705b7724c3d9fbe1b2&chksm=ea97234edde0aa586c8115f5eda113ca0ea18c04ede5002327dc6390698eec46066457c4971b&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/veeam-warns-of-critical-bugs-in-veeam-one-monitoring-platform/  
  
  
题图：  
Pexels  
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
  
