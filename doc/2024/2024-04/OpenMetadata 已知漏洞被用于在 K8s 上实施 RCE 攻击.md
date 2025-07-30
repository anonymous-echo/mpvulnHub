#  OpenMetadata 已知漏洞被用于在 K8s 上实施 RCE 攻击   
Becky Bracken  代码卫士   2024-04-18 17:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**微软威胁情报团队指出，OpenMetadata 的开源元数据仓库中存在多个已知漏洞，自4月起就遭活跃利用，可导致威胁行动者对未修复的 Kubernetes 集群发动远程代码执行攻击。**  
  
  
  
OpenMetadata 是一款用作元数据管理工具和中央仓库的开源平台。今年3月初，研究人员发布了五个漏洞（CVE-2024-28255、CVE-2024-28847、CVE-2024-28253、CVE-2024-28848和CVE-2024-28254），影响v1.3.1及之前版本。  
  
虽然很多网络安全团队可能错过了该公告，但攻击者们抓住这次机会入侵 Kubernetes 环境并用于密币挖掘。微软研究员 Yossi Weizman 解释称，“在这个案例中，易受攻击的 Kubernetes 工作负载被暴露在互联网中遭到攻击。”虽然网络犯罪分子会用于挖掘密币，但他提醒称攻击者一旦进入 K8s 集群，还可从事大量恶意活动。他补充道，“具体而言（并非该案例），一旦攻击者控制了集群中的工作负载，他们可尝试利用该访问权限进行横向移动，包括在集群内部和外部资源。”  
  
建议OpenMetadata 管理员更新版本，使用强认证并重置所用的任何默认凭据。****  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[OWASP 发布十大开源软件风险清单（详解版）](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519303&idx=1&sn=df6dc31715e4c8d70ad22fe31af7eb03&chksm=ea94bd2ddde3343b6e37f517febd2d68bba0fe206dde6bab42bf696389f1ca4723bbdf8ccf78&scene=21#wechat_redirect)  
  
  
[谷歌GKE 配置不当可导致K8s 集群遭接管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518751&idx=2&sn=c0dee1349c763444a9b530c13df8884c&chksm=ea94bb75dde33263fdd0a9b306d42de1431658392cc621138a3d48ebcb8a3a35e0c3ee4f7b6f&scene=21#wechat_redirect)  
  
  
[开源容器原生工作流引擎 Argo Workflows 可被用于攻击 K8s 集群](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506552&idx=2&sn=0709599afc13daa3e75842af50683d54&chksm=ea94eb12dde362042ecc90f6ca1d593486aa2fffdcef35a2968e8d320340872c3b9b19fd60e7&scene=21#wechat_redirect)  
  
  
[Kubernetes CLI 工具被曝严重漏洞，谷歌K8S也受影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490318&idx=2&sn=c133ecd43f5cbc83f41c71f3f72b0849&chksm=ea972a64dde0a37224b58f514da56d6dbd618546a1c9df151d5b7faac527dc64be1fcc2bef31&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.darkreading.com/cloud-security/active-kubernetes-rce-attack-relies-on-known-openmetadata-vulns  
  
  
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
  
