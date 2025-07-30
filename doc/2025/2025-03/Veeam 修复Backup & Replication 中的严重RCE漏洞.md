#  Veeam 修复Backup & Replication 中的严重RCE漏洞   
Ionut Arghire  代码卫士   2025-03-21 18:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周，Veeam 宣布修复了 Backup &Replication 产品中的一个严重漏洞，可导致攻击者远程执行任意代码。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTQJ9PYncDNOYhrAjpgUgfQFwAaQeLtqeyLib9ra3fwlCLeMdYic3xiaibfxU6kibxibKaLXpgPm9YDEXXw/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞的编号是CVE-2025-23120（CVSS评分9.8），可导致“认证域用户远程执行代码”，Backup & Replication 12.3.0.310及之前版本 12 builds受影响。该公司建议升级到修复该漏洞的版本12.3.1 (build 12.3.1.1139)。  
  
报送该漏洞的网络安全公司 watchTowr提到，该漏洞的根因在于 Veeam 反序列化机制中的一个更广泛的问题，而Veeam 未能正确修复。该公司提到，Veeam Backup & Replication 通过实现一个允许列表，虽然遵循控制可被反序列化的类的行业标准，但未能执行正确的反序列化程序，因为其中的一个被允许类导致内部反序列化，而它执行的是拦截列表。  
  
Veeam 对此前已报送反序列化漏洞的补丁涉及将条目添加到拦截列表，而且基于该配置以及 Backup & Replication 的大型代码库，新的可用于实现代码执行的反序列化工具仍可被找到。  
  
研究人员提到，CVE-2025-23120可能与2024年9月披露的一个严重RCE漏洞CVE-2024-40711之间存在关联。后者在不到一个月的时间后被用于勒索攻击中。它也可能与CVE-2024-42455之间存在关联，后者是一个高危漏洞，可导致“在备份服务器上‘用户和角色’设置中拥有分配角色的认证用户，连接到远程服务并通过发送一个序列化的临时文件收集利用不安全的反序列化，从而可通过服务账户权限删除系统上的任何文件。”  
  
研究人员提到，重点是攻击者可通过搜索产品库中未被列入拦截清单且可能造成恶意影响的反序列化工具，来识别 Backup & Replication 中的类似问题。watchTowr 公司就找到了两个此类问题（被合称为 CVE-2025-23120），其中一个可通过修改CVE-2024-40711的PoC代码遭利用。  
  
watchTowr 公司还提醒称，虽然利用该新漏洞要求攻击者是登录状态，但“认证要求十分低”。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Veeam 提醒注意VSPC中的严重RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521684&idx=1&sn=b5ba5835dc8937327b3ded698979f0f2&scene=21#wechat_redirect)  
  
  
[Veeam 修复5个严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520714&idx=1&sn=df4e06a4fa7f19703c54eeb2ccf244d6&scene=21#wechat_redirect)  
  
  
[Veeam：Backup Enterprise Manager 中存在严重的认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519550&idx=2&sn=6b4de50a6ef98b37be097aae6daafa64&scene=21#wechat_redirect)  
  
  
[Veeam 修复备份管理平台中的RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519438&idx=1&sn=4e26daf80a580f4ffca69990e4991525&scene=21#wechat_redirect)  
  
  
[Veeam ONE 监控平台存在多个严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518080&idx=3&sn=186f168b319049fd88ec7557cb2458e1&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/veeam-patches-critical-vulnerability-in-backup-replication/  
  
  
  
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
  
