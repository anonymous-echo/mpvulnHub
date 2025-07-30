#  SAP 修复多个高危漏洞   
Ionut Arghire  代码卫士   2023-05-11 17:46  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX6Inlu2SGYBwg77ZPry2yAAgEMG81vlTyibUKjGaL84ZXJicHMLoQhia6qGkiaNGZjNnwokM7Ql83icObA/640?wx_fmt=png "")  
  
**德国企业软件商 SAP 在本周的五月安全补丁星期二，发布了18个新的安全说明，其中包括多个严重漏洞的“重要”说明。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQqdYias9v5qHLxMsIOjPGgnibVhYe1J5WoRRkCXYuRrelZN8LszOenm2ib0NU27FiaqgFibDuBRlqmtyQ/640?wx_fmt=png "")  
  
  
在这些“重要”说明中，其中一个和位于 SAP 3D 可视化企业许可证管理的 Reprise 许可证管理器 (RLM) 14.2 组件中的五个漏洞有关。其中最严重的漏洞是CVE-2021-44152（CVSS评分9.8），它是认证/授权检查不当漏洞，可导致未认证攻击者更改任意用户账户的密码。  
  
NIST 在一份安全公告中提到，“该漏洞可导致攻击者更改任意已知用户的密码，从而阻止合法用户访问系统并导致攻击者完全访问用户账户。”在余下的四个严重漏洞中，其中三个是高危漏洞，一个是中危漏洞。  
  
企业安全公司 Onapsis 解释称，手动禁用受影响的 RLM web 接口可修复该漏洞。  
  
第二个重要的安全说明修复了位于 BusinessObjects 情报平台中的多个信息泄露漏洞，它们是CVE-2023-28762（CVSS评分9.1）。其中最严重的漏洞可导致攻击者以管理员权限登录，检索任意已登录用户或服务器的登录令牌且无需用户交互。这可导致攻击者模拟该平台上的任意用户，访问并修改数据，使得系统部门或完全不可用。  
  
Onapsis 对SAP补丁分析指出，该安全说明替换了2022年发布的五个安全说明，解决位于 BusinessObjects 中的信息泄漏漏洞，而这些漏洞已在本周二更新。  
  
SAP 本周发布了七个新的高危说明，解决位于 NetWeaver、IBP Excel 附件、PowerDesigner (Proxy)、Commerce、GUI for Windows 以及 SAPUI5 中的漏洞。同时周二还修复了七个中等优先级和两个低优先级的说明。  
  
Onapsis 公司指出，SAP 在本月更新但并未在发布说明中提到的另一份安全说明中，带来了 Business Client 中所包含的 Chromium 浏览器的最新补丁。鉴于谷歌在数周前修复了两个 Chrome 0day，因此这一安全更新也并不令人惊讶。  
  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[【Black Hat】SAP漏洞已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513628&idx=1&sn=d47438e7ab536d8f38c3cc8dd64af9b0&chksm=ea948776dde30e60080335212664479f70129c02d436426a1f71c0f2e9a00e28f352b049b00a&scene=21#wechat_redirect)  
  
  
[SAP 严重漏洞可导致供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510205&idx=1&sn=67bf82c9a4e12472004c1640e2ac783b&chksm=ea9499d7dde310c151feaff7a553b0bdd95c645f7cb87f1be6ecce063acce2bb74a15a2750c6&scene=21#wechat_redirect)  
  
  
[SAP SolMan 严重漏洞的自动化 exploit 代码遭公开](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247500895&idx=3&sn=732b9f338ee0e4c9935a826c9af711d7&chksm=ea94f535dde37c2315fc6eab7c89d5367078f424895d57321fed9bb26b0018574142f838d550&scene=21#wechat_redirect)  
  
  
[前脚修复，后脚放 PoC：马上修复这个严重的SAP Recon 漏洞！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494103&idx=1&sn=e9e6e02258206c4caa3e7b35c54ac0a6&chksm=ea94d8bddde351ab60fbf2283b3ab5d830d9d81d450469c1bf9a99826511061c8015fe9a20e9&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/sap-patches-critical-vulnerabilities-with-may-2023-security-updates/  
  
  
题图：Pixabay License  
  
  
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
  
