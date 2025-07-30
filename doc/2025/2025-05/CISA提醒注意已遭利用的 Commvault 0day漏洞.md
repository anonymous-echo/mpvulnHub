#  CISA提醒注意已遭利用的 Commvault 0day漏洞   
Ionut Arghire  代码卫士   2025-05-27 10:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**CISA提到，正遭利用的 Commvault 0day漏洞可能是更广范围的软件即服务 (SaaS) 解决方案的一部分。**  
  
**该漏洞的编号是CVE-2025-3928（CVSS 评分8.7），可导致远程攻击者创建和执行 webshell，完全攻陷易受攻击的实例。Commvault 在今年2月末修复了该漏洞，并提醒称微软提到可疑的一个国家黑客威胁行动者已经利用该漏洞黑入 Azure 环境。4月末，CISA将该漏洞纳入必修清单。**  
  
**5月早些时候，微软更新安全公告提醒称，这些威胁行动者们“可能已经访问了某些 Commvault 客户用于认证其 M365 环境的应用凭据子集。”为了帮助客户捕获潜在攻陷情况，Commvault 已提供与所观察到的攻击活动相关的妥协指标 (IoCs)。该公司还更改了凭据并增强了监控规则。**  
  
**Commvault 公司披露称，该恶意活动仅影响与微软共有的少量客户，但并不涉及Commvault 所存储的客户备份的越权访问权限。**  
  
**CISA提到，攻击者可能已利用CVE-2025-3928访问了托管在 Azure 中的 M365 备份 SaaS 解决方案的客户端机密，导致“Commvault 客户的 M365 环境”遭越权访问，而“Commvault”在该环境中“存储了应用机密”。CISA 提到，“CISA 认为该威胁活动可能是更大攻击的一部分，该攻击的目标是各种具有默认配置和提升的权限的 SaaS 企业云应用。”**  
  
**CISA 建议组织机构监控 Entra 审计日志，将非常规登录视作可疑行为，捕获内部威胁，执行有条件的访问策略，更改 Commvault Metallic 应用机密，更改应用凭据，查看管理员权限并执行强健的 M365安全机制。**  
  
**对于本地部署而言，组织机构应当限制对 Commvault 管理界面的访问权限、检测并拦截路径遍历尝试、拦截可疑的文件上传、应用必要的补丁，并监控来自异常目录的活动。**  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[NIST、CISA联合提出漏洞利用概率度量标准](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523082&idx=2&sn=4d5a25d58482d98bdb3b13320e03bb92&scene=21#wechat_redirect)  
  
  
[CISA为CVE计划续期11个月，MITRE 成立CVE基金会防范](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522769&idx=2&sn=550a6097b86ddca08a77c2e694b9e854&scene=21#wechat_redirect)  
  
  
[CISA：速修复已遭利用的 CentreStack 和 Windows 0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522701&idx=2&sn=0b8f46ac41b6d62102b7ec1c02b25f60&scene=21#wechat_redirect)  
  
  
[CISA：Edimax 摄像头中的严重0day漏洞已遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522437&idx=1&sn=fa13f44a7ac5f969c2545cd409208ea5&scene=21#wechat_redirect)  
  
  
[CISA称将不会停止监控俄罗斯网络威胁](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522418&idx=2&sn=fcea7c698026178b462b6b2369a3a5a2&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/companies-warned-of-commvault-vulnerability-exploitation/  
  
  
  
题图：  
Pixabay Licen  
se  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
