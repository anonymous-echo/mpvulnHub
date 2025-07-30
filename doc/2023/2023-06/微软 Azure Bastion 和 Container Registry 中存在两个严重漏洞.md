#  微软 Azure Bastion 和 Container Registry 中存在两个严重漏洞   
Ravie Lakshmanan  代码卫士   2023-06-15 17:44  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRMqB8dM1tiajzZglFy2PMGvn76vqY5ZO8HppnftCO1bN4cy4CY1zmSg0amjBAZAHewubO3mlYluZg/640?wx_fmt=gif "")  
  
**微软 Azure Bastion 和 Azure Container Registry 中存在两个严重该漏洞，可用于执行XSS攻击。**  
  
  
Orca 公司的安全研究员表示，“这些漏洞可导致攻击者越权访问受陷 Azure 服务iframe中的受害者会话，导致严重后果如越权数据访问、越权修改以及Azure 服务iframe中断等。”  
  
当威胁行动者将任意代码注入受信任的网站中并最后在用户每次访问执行时，就会触发XSS攻击。这两个漏洞是 Orca 利用 postMessage iframe中一个漏洞时发现的，可导致 Windows 对象之间进行跨源通信。这意味着该漏洞可被用于通过iframe标记在远程服务器中嵌入端点并最终执行恶意 JavaScript 代码，从而攻陷敏感数据。  
  
然而，要利用这些弱点，攻击者必须在不同的 Azure 服务上开展侦查活动，找到 Azure 门户中的易受攻击端点，它们可能缺失 X-Frame-Options 标头或弱内容安全策略 (CSPs)。  
  
Ben Shitrit 解释称，“攻击者成功将iframe嵌入远程服务器后，会接着利用配置不当的端点。他们主要关注 postMessages 句柄，用于处理远程事件如 postMessages。”通过分析从 portal.azure[.]com 发送给该iframe的合法 postMessages，攻击者通过将易受攻击的iframe嵌入到受其控制的服务器并创建用于交付恶意 payload 的 postMesage 句柄，就可构建合适的 payload。”随后将受害者诱骗访问受陷端点，“恶意 poastMessage payload 就被交付到嵌入式的iframe中，触发 XSS 漏洞并在受害者情境中执行攻击者的代码。”  
  
从研究员发布的 PoC 演示来看，他们构造的 postMessage 可用于操控 Azure Bastion Topology View SVG 导出器或 Azure Container Registry Quick Star，执行 XSS payload。  
  
研究员在2023年4月13日和5月3日将这两个漏洞告知微软，后者推出补丁予以修复。Azure 用户无需任何附加操作。一个多月前，微软修复了 Azure API 管理服务中的三个漏洞，它们可被用于获取对敏感信息或后端服务的访问权限。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[研究员在微软 Azure API 管理服务中发现3个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516392&idx=3&sn=f563d9d06d17140943a9006f9816fecd&chksm=ea94b182dde33894747c1e2aa9ddbd52a923d8f1cc8ec0edd712caa946b58d97a9ac1bda8ecf&scene=21#wechat_redirect)  
  
  
[四款微软Azure服务存在漏洞，可导致云资源遭越权访问](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515363&idx=3&sn=6c939ad71b9754325cf5e804212ce38e&chksm=ea948d89dde3049f9674c7caff6a7a10ad9243925974600a40bc322cfba7198f6d8f4e045dbf&scene=21#wechat_redirect)  
  
  
[微软Azure新漏洞可导致RCE，研究员获3万美元奖励](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515363&idx=2&sn=36927e449388a6dc1fcc5e7ccbf92a2e&chksm=ea948d89dde3049ffbff2cf56bcfbaa5d4e844e193a9391619d310ac4f075848d0fc66a2cf00&scene=21#wechat_redirect)  
  
  
[微软悄悄修复Azure跨租户数据访问高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515121&idx=1&sn=a174aa208e22a8d97fae0aa69a4777b2&chksm=ea948a9bdde3038d87dd9ce4fd4207e50cee5c030640d32b5ae879eac287877c6505152caf15&scene=21#wechat_redirect)  
  
  
[微软Azure SFX漏洞可导致Service Fabric集群遭劫持](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514269&idx=2&sn=61fe8c8c8b4505c23ab577d13989e73c&chksm=ea9489f7dde300e13728eb2f26e16b58db650e35dc327f5498c2e7732678f4cf0397a44ff4b0&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2023/06/severe-vulnerabilities-reported-in.html  
  
  
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
  
