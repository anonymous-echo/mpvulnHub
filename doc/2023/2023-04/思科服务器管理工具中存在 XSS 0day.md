#  思科服务器管理工具中存在 XSS 0day   
Sergiu Gatlan  代码卫士   2023-04-27 17:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**今天，思科披露称其 PCD 软件中存在一个 0day 漏洞（CVE-2023-20060），可用于XSS 攻击活动中。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRg0SCnz2KOVbCs36hD1ib3BuChC6Da49NKVQS4q9eWGT72A03KyJplVkavauFGBVrGVMhRwr4MO8g/640?wx_fmt=gif "")  
  
  
该服务器管理工具可使管理员在服务器上执行缓解或升级任务。该漏洞位于思科 PCD 14 的web 管理接口中，是由北约网络安全中心的成员 Pierre Vivegnis 发现的。成功利用该漏洞可导致未认证攻击者远程发动XSS攻击但需要用户交互。  
  
思科解释称，“该漏洞存在的原因是基于 web 的管理接口未能正确验证用户提供的输入。攻击者可说服接口用户点击构造链接，从而利用该漏洞。成功利用可导致攻击者在受影响的接口上下文中执行任意脚本代码或访问敏感的基于浏览器的信息。”  
  
虽然思科共享了关于该漏洞的影响，但下个月某些时候才会发布安全更新。目前尚不存在删除该攻击向量的应变措施。幸运的是，思科 PSIRT 尚未找到该漏洞遭在野利用的证据且并未发现公开的利用代码。  
  
  
**仍未修复的另外一个 0day**  
  
  
  
思科还修复了已存在公开利用代码的另外一个高危IP Phone 0day (CVE-2022-20968)，该漏洞在2023年12月早些时候披露。  
  
思科 PSIRT 团队当时提醒称“已发现 PoC 利用代码”，以及“该漏洞已被公开讨论。”  
  
虽然思科当时指出将在2023年1月发布补丁，但目前仍未修复。受该漏洞影响的设备包括运行7800和8800系列固件版本14.2及更早版本的思科 IP 电话。  
  
尽管思科目前并未发布相关环节措施，但建议管理员应用临时缓解措施，即禁用受影响设备上的思科发现协议。思科当时提醒称，“这并非小变动，要求企业评估对设备的潜在影响以及部署该变更的最佳方式。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[思科决定不修复已达生命周期路由器中的认证绕过0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513869&idx=2&sn=7199bcc2306ffa52728d244b3157c9c6&chksm=ea948667dde30f7126092d37c3a6b6ec03c1517c0a95065187739d5cfc9e2b810e54fa40d8b9&scene=21#wechat_redirect)  
  
  
[思科不打算修复VPN路由器 RCE 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512438&idx=1&sn=563e5fbc7e61730cf40397cd09414e2b&chksm=ea94801cdde3090ad98fcb1524ccb001df9942040fddf238640160b7dab3a84c77eeef57ee7e&scene=21#wechat_redirect)  
  
  
[VPN路由器存在 RCE 0day，思科不打算修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507288&idx=1&sn=35ea226a198d2e8b498fc0594f0c9e4c&chksm=ea94ec32dde365247ce79386abc905a55fa29ff709ced9085f116a97b44f37d5af3b6c853711&scene=21#wechat_redirect)  
  
  
[思科 Security Manager 12个0day PoC 被公开，多个严重 0day仍未修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247497426&idx=1&sn=f84ec3052c9eab63db663d018b5a5f2a&chksm=ea94c7b8dde34eae26ee61957aae24db2ba41d21dabe9df651697c4653b0de2c24442ebaf756&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/cisco-discloses-xss-zero-day-flaw-in-server-management-tool/  
  
  
题图：Pexels License  
  
  
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
  
