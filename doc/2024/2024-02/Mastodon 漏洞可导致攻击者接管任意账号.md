#  Mastodon 漏洞可导致攻击者接管任意账号   
Bill Toulas  代码卫士   2024-02-04 18:26  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**免费开源的去中心化社交网络平台 Mastodon 修复了一个严重漏洞，它可导致攻击者模拟并接管任何远程账号。**  
  
  
自马斯克收购推特后，Mastodon 变得流行起来，目前号称拥有近1200万名用户，遍布1.1万个实例。Mastodon 上的实例（服务器）具有自主性但是通过名为 “federation” 的系统联网社区，拥有自己的指南和策略，由提供该基础设施并以服务器管理员的身份行动的所有人控制。  
  
该漏洞的编号是CVE-2024-23832，是由在 Mastodon 中的来源验证不充分造成的，可导致攻击者模拟用户并接管其账号。该漏洞的CVSS v3.1评分为9.4，影响3.5.17、4.0.13、4.1.13和4.2.5之前的所有 Mastodon 版本。该漏洞已在昨天发布的 4.2.5 版本中修复。建议所有 Mastodon 服务器管理员尽快更新至最新版本。  
  
Mastodon 并未发布漏洞详情以免遭利用，不过承诺将在2月15日披露更多细节。Mastodon 用户无法采取任何措施解决该安全风险，不过应确保实例的管理员已在2月中旬更新至安全版本；否则他们的账号将易遭劫持。好在 Mastodon 选择通过醒目的提示对服务器管理员提出告警，因此已被活跃维护的所有实例应当可以看到该更新并在接下来的几天内更新至安全版本。  
  
Mastodon 账号遭模拟和接管可造成重大风险，影响个人用户、社区和平台的完整性，因此CVE-2024-23832是一个严重漏洞。  
  
2023年7月，Mastodon 团队修复了另外一个严重漏洞CVE-2023-36460并将其命名为 “TootRoot”，它可导致攻击者发送 “toots（类似于推文）”，在目标实例上创建 web shell。攻击者可利用该漏洞完全攻陷 Mastodon 服务器，从而访问用户敏感信息、通信以及植入后门。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[严重的 TootRoot 漏洞可导致Mastodon 服务器遭劫持](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516985&idx=2&sn=1314af5aa885e4849eef0319cfc6f5f1&chksm=ea94b253dde33b45266932db87448f0614dda574b5bb33e1598ef3acd97302e9bd4ab2ae157a&scene=21#wechat_redirect)  
  
  
[Mastodon 用户易受密码窃取攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514671&idx=2&sn=01488cff40e9435d1ee584d20970714d&chksm=ea948b45dde302533009ce4b9a55ae959c7e279f6c448ff79b402c6c7c1e161a108d6a3d835f&scene=21#wechat_redirect)  
  
  
[谷歌GKE 配置不当可导致K8s 集群遭接管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518751&idx=2&sn=c0dee1349c763444a9b530c13df8884c&chksm=ea94bb75dde33263fdd0a9b306d42de1431658392cc621138a3d48ebcb8a3a35e0c3ee4f7b6f&scene=21#wechat_redirect)  
  
  
[严重的蓝牙漏洞已存在多年，可用于接管安卓、iOS 和 Linux 设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518319&idx=1&sn=5714524d6170f4fef9f36a2a9801b556&chksm=ea94b905dde3301385c1f828c130d4e404acb8a7addf6ed7ea4155f5063d9b70b0d539ec90eb&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/mastodon-vulnerability-allows-attackers-to-take-over-accounts/  
  
  
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
  
