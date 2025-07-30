#  Fortinet 修复 Fortigate SSL-VPN 设备中严重的 RCE 漏洞   
Lawrence Abrams  代码卫士   2023-06-12 18:22  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**Fortinet 发布新的 Fortigate 固件更新，修复了一个位于 SSL VPN设备中未披露的严重的预认证远程代码执行漏洞。**  
  
  
  
  
该修复方案在上周五 FortiOS 固件版本6.0.17、6.2.15、6.4.13、7.0.12和7.2.5中发布。虽然发布公告中并未提及，但安全专业人员和管理人员提到，这些更新悄悄地修复了一个将在6月13日披露的严重的 SSL-VPN RCE漏洞。  
  
法国网络安全公司 Olympe Cyberdefense 指出，“这个缺陷将使敌对代理通过VPN进行干扰，即使激活MFA也无济于事。截止目前，所有版本将受影响，我们正在等待在2023年6月13日的发布，证实该信息。”  
  
一直以来，Fortinet 公司在披露严重漏洞前推出安全补丁，使客户在威胁行动者逆向补丁之前有足够的时间更新设备。Lexfo 安全公司的漏洞研究员 Charles Fol 发布更多信息，表示新的 FortiOS 更新中包括一个由他和 Rioru 发现的一个严重的 RCE 漏洞。  
  
Fol 在推文中表示，该漏洞编号是 CVE-2023-27997，是可达的预认证漏洞，位于所有的 SSL VPN 设备上。他建议用户修复 Fortigate 并提到将在不久后发布漏洞详情。Fol 证实称它是 Fortinet 管理员应当紧急修复的补丁，因为威胁行动者将很快分析并发现该补丁。  
  
从 Shodan 搜索的结果来看，互联网可触及超过25万个 Fortigate 防火墙，由于该漏洞影响所有之前版本，因此多数设备可能遭暴露。  
  
之前，威胁行动者会在补丁发布几天后就利用这些 SSL-VPN 漏洞，通常用于获得对网络的初始访问权限，进而执行数据盗取和勒索攻击。因此，管理员必须尽快应用这些 Fortinet 安全更新。  
  
Fortinet 公司回应称，“我们正在与客户及时沟通，以便最佳保护他们所在组织机构的安全。在一些情况下会包含机密的客户提前沟通，如在公告中发布提前预警，使客户能够进一步增强安全态势，随后才会像更多的客户公开发布这些公告。这一流程遵照负责任披露的最佳实践，确保客户具有所需的即时信息，以便做出基于风险的充分决策。如需访  
问 Fortinet 的负责任披露流程，请访问 Fortinet 产品安全时间响应团队 (PSIRT) 页面。”  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Fortinet 修复FortiADC 和 FortiOS 中的多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516406&idx=3&sn=f6d52c7913cb9a7127079a424f287d22&chksm=ea94b19cdde3388a41d9382c14e8649d4db7f27382de8b638a8c2430d9fb7a6e3125a60ceed6&scene=21#wechat_redirect)  
  
  
[Fortinet 修复数据分析解决方案中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516234&idx=2&sn=8b8cbd3bbef796e7781c52396c37618f&chksm=ea94b120dde33836274567a92fa01a00f6e40b1b29565d989648c9eeada3ac326405a7a9e7d9&scene=21#wechat_redirect)  
  
  
[Fortinet FortiOS漏洞被用于攻击政府实体](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515912&idx=1&sn=0d48724c08d4d63949a7142683b6fdd7&chksm=ea948e62dde30774b504e3a089bab575daf337854bba663d40f81014b5672260b74230a007a3&scene=21#wechat_redirect)  
  
  
[Fortinet：注意这个严重的未认证RCE漏洞！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515862&idx=1&sn=d2ef6b5ab51eba3e97af531d1a8b212b&chksm=ea948fbcdde306aa2d71b31b492175fc0c01a69233601e35fc9fee73fbfbae62668f3aaaffb2&scene=21#wechat_redirect)  
  
  
[Fortinet修复两个严重的RCE漏洞，其中一个两年前就发现？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515647&idx=1&sn=b8f00a46755a56f7d9aed5ae56c1b4e4&chksm=ea948c95dde305837c4ef5d418e236f9718061ffd9b877fde4fc8a267a7bf0b9910d885f6ea4&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/fortinet-fixes-critical-rce-flaw-in-fortigate-ssl-vpn-devices-patch-now/  
  
  
题图：Pexels License  
  
  
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
  
