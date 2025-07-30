#  思科提醒注意严重的DoS漏洞   
Sergiu Gatlan  代码卫士   2025-01-23 08:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**思科发布安全更新，修复了位于ClamAV 中的拒绝服务 (DoS) 漏洞，并表示漏洞的 PoC 利用代码已出现****。**  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRf5iaSdYQdDyLianbJN9AmomZXnglGTIy9ibAs6aB7Jia3wczJlibxrRckR8aSl2NbG7WJw8Yvlpe6qag/640?wx_fmt=gif&from=appmsg "")  
  
  
该漏洞的编号是CVE-2025-20128，是由位于OLE2解密例程中的一个堆缓冲溢出漏洞造成的，可导致未认证的远程攻击者在易受攻击设备上触发DoS 条件。  
  
如该漏洞遭成功利用，则可导致 ClamAV 反病毒扫描流程崩溃，从而阻止或延迟后续扫描操作。思科解释称，“攻击者可提交包含OLE2内容的构造文件供受影响设备上的ClamAV扫描。成功利用该漏洞可导致攻击者终止ClamAV扫描流程，导致在受影响软件上触发DoS条件。”不过在今天发布的安全公告中，思科提到即使遭到成功攻击，系统的整体稳定性也不会受影响。  
  
易受攻击的产品清单包括适用于Linux、Mac和Windows平台的 Secure Endpoint Connector。该解决方案有助于将思科Secure Endpoint 审计日志和事件导入安全信息和事件管理 (SIEM) 系统如微软的Sentinel。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRf5iaSdYQdDyLianbJN9AmomFe3YUetyMyNSnPOoM95Iv8EAK9iban3jgZYibHwh3M6J4CKA8vgWodxg/640?wx_fmt=png&from=appmsg "")  
  
  
**PoC 已出现，无活跃利用**  
  
  
  
虽然思科产品安全事件响应团队 (PSIRT) 表示并未发现在野利用的证据，但表示CVE-2025-20128的利用代码已存在。思科PSIRT指出，“思科 PSIRT 发现本公告中所述漏洞的PoC利用代码。”  
  
思科还修复了位于思科 BroadWorks 中的 DoS 漏洞 (CVE-2025-20165) 和位于思科Meeting Management REST API 中的一个严重的提权漏洞 (CVE-2025-20156)，可导致黑客获得未修复设备上的管理员权限。  
  
去年10月份，思科还修复了位于ASA和FTD软件中的另外一个 DoS 漏洞 (CVE-2024-20481)，而这是在2024年4月针对思科 Secure Firewall VPN设备的大规模暴力攻击活动中发现的。  
  
一个月之后，它还修复了一个满分漏洞CVE-2024-20418，可导致攻击者以root权限在易受攻击的URWB工业访问点上运行命令。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[思科IOS 漏洞可导致未认证的远程DoS 攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519204&idx=2&sn=6fc646b9575f6837ef0f55d569c11709&scene=21#wechat_redirect)  
  
  
[多个高危漏洞可导致思科交换机和防火墙遭 DoS 攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517453&idx=2&sn=251402ddfd4c8a150b8758f1c605b2af&scene=21#wechat_redirect)  
  
  
[思科满分漏洞可使黑客以root身份运行任意命令](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521416&idx=1&sn=dd174cdf4dec9fc76bae7be5c63bbd68&scene=21#wechat_redirect)  
  
  
[思科修复已有 PoC 的根提权漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520683&idx=1&sn=00f735c28afb0e6cc70f919cade9dc5c&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/cisco-warns-of-denial-of-service-flaw-with-poc-exploit-code/  
  
  
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
  
