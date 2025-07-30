#  Ivanti 披露两个新0day，其中一个已遭利用   
Sergiu Gatlan  代码卫士   2024-02-01 17:18  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**今天，Ivanti 公司提醒称又有两个漏洞影响 Connect Secure、Policy Secure 和 ZTA 网关，其中一个0day 已遭活跃利用。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQGEhoXQliaibsbCX8AWBMwIbNqcndK5zkwYuXsG1Nc01IKY86UHfCPukerHibddq3g3VcicJo2C4ibj4g/640?wx_fmt=gif&from=appmsg "")  
  
  
CVE-2024-21893是一个服务器端请求伪造漏洞，位于网关的 SAML 组件中，可被攻击者用于绕过认证并访问易受攻击设备上的受限制资源。第二个0day 漏洞是CVE-2024-21885，位于网关的 web 组件中，可使攻击者将权限提升至管理员。  
  
Ivanti 公司指出，“在调查1月10日收到的位于 Ivanti Connect Secure、Ivanti Policy Secure 和 ZTA 网关中的漏洞过程中，我们发现了新漏洞，它们影响所有受支持版本即版本9.x和22.x。目前未有证据表明任何客户受CVE-2024-21888漏洞的影响。我们仅发现少数客户受CVE-2024-21893的影响。立即采取措施确保完全受保护至关重要。”  
  
Ivanti 公司已发布安全更新，修复一些受影响的 ZTA 和 Connect Secure 版本，并为仍然等待补丁的设备发布缓解指南。  
  
  
**补丁发布**  
  
  
  
今天，Ivanti 公司还为1月初披露的另外两个 0day 漏洞，即认证绕过漏洞 (CVE-2023-46805) 和命令注入漏洞 (CVE-2024-21887)。自1月11日起，这两个漏洞就被组合用于在易受攻击的 ICS、IPS 和 ZTA 网关上部署恶意软件，发动大规模攻击活动。  
  
Ivanti 公司还发布缓解措施，拦截攻击尝试和恢复指南，帮助恢复易受攻陷的设备并恢复服务。  
  
威胁监控平台 Shadowserver目前追踪超过2.47万台被暴露在互联网的 ICS VPN 网关，其中超过7200台位于美国（Shodan 显示超过2.2万台 Ivanti ICS VPN 暴露在网络）。Shadowserver 还日常监控全球受攻陷的 Ivanti VPN 实例情况，单在1月30日就发现了460多台受陷设备。  
  
CISA 也发布了2024年的首份紧急指令 (ED24-01)，要求联邦机构立即缓解CVE-2023-46805和CVE-2024-21887漏洞，以应对多个威胁组织的大规模利用。组合利用这两个漏洞可导致攻击者通过部署后门在受害者网络中横向移动、盗取数据并设立持久访问权限。目前为止发现的受害者包括全球政府和军事组织机构，国家电信企业，国防承包商，银行、金融和会计组织机构，以及航空、航天以及技术企业。这些受害者规模不一，有小企业也有最大的跨国集团，其中包括多个行业的多家财富500强公司。  
  
Mandiant 公司发现这些大规模攻击中部署了五个自定义恶意软件链，帮助威胁人员窃取凭据、部署 webshell 并释放其它恶意 payload。Volexity 和 GreyNoise 也发现攻击者在某些受害者的失陷系统中部署 XMRig 密币挖矿机和基于Rust 的恶意软件payload。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[第三个 Ivanti 漏洞已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518721&idx=2&sn=0fecc3da2d3d00906eb9f4f79279a328&chksm=ea94bb6bdde3327dc06586f79bb98cb915165183da490c1b063cf84fb4571cce6ae8e8396b99&scene=21#wechat_redirect)  
  
  
[严重的Ivanti EPM 漏洞可导致黑客劫持已注册设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518594&idx=1&sn=42344cd84f041e0bd0049ef5c7bbdf84&chksm=ea94b8e8dde331fe2a1df497c6a9068b0b510c2924d9229f7c28997fee0d5b1c8a1d81cd78aa&scene=21#wechat_redirect)  
  
  
[Ivanti 修复 Avalanche 中的13个严重 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518459&idx=2&sn=11cb31fa8a53f1561ec28a3e9a63da6e&chksm=ea94b991dde33087c9606baa5ebb64e71528283f676f497d3123ca31f84cc1ce1f3e971e8184&scene=21#wechat_redirect)  
  
  
[Ivanti 紧急修复 API 认证绕过0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517421&idx=1&sn=31756dd565b1bbd216e954def83c61dc&chksm=ea94b587dde33c91e83a737ae3eb0a14c48a427523b94dba12823b03eac1cecf97a890e21afa&scene=21#wechat_redirect)  
  
  
[挪威政府机构遭攻击，黑客利用的不止IT巨头 Ivanti的一个0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517282&idx=1&sn=92bc54d50120e90cdb14ffdc9575e7e5&chksm=ea94b508dde33c1eb06b110c0e5f8a197bfcb980488faddce9fee996ea1be88dc50821b49082&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/ivanti-warns-of-new-connect-secure-zero-day-exploited-in-attacks/  
  
  
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
  
