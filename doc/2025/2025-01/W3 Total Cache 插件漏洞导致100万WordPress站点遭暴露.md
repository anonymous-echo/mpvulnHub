#  W3 Total Cache 插件漏洞导致100万WordPress站点遭暴露   
Bill Toulas  代码卫士   2025-01-17 09:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQzBMPIgrH4bQBUsv9hs5UQBvXOmhogEEDkOVof3mWA0OyoqGSzkYbng6gQdKnDicTX8Vl2n8oZtdw/640?wx_fmt=gif&from=appmsg "")  
  
  
**安装在100多万个WordPress 站点上的W3 Total Cache 插件中存在一个严重漏洞，可导致攻击者访问多种信息，如基于云的app 上的元数据。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQzBMPIgrH4bQBUsv9hs5UQBvXOmhogEEDkOVof3mWA0OyoqGSzkYbng6gQdKnDicTX8Vl2n8oZtdw/640?wx_fmt=gif&from=appmsg "")  
  
  
该插件使用多种缓存技术来优化网站的速度、减少加载时间并提高其SEO排名。该漏洞的编号是CVE-2024-12365,。尽管开发人员已在该产品的最新版本中发布修复方案，但成千上万个网站仍然必须安装已修复变体。  
  
  
**漏洞详情**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQzBMPIgrH4bQBUsv9hs5UQNop7quGcicIkwiczgQZ3ReHicGqonYFcKm1xvmjusJPsfSleup7zibW4TA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
Wordfence 提到，该漏洞是因为2.8.2及之前所有版本中的 “is_w3tc_admin_page” 中缺少能力检查而引发的，可导致攻击者访问该插件的安全随机值并执行越权操作。  
  
如果攻击者已认证且至少是订阅级别，则利用该漏洞是很可能实现的。利用该漏洞造成的主要风险是：  
  
- 服务器端请求伪造 (SSRF)：提出的web请求可能泄露敏感数据，包括基于云的应用上的实例元数据。  
  
- 信息泄露  
  
- 服务滥用：使用缓存服务限制，影响站点性能并可造成成本上升。  
  
  
  
鉴于该漏洞造成的真实影响，攻击者可利用网站的基础设施将请求代理至其它服务并利用所收集信息进一步发动攻击。受影响用户的最佳应对措施是升级至 W3 Total Cache 最新版本2.8.2，修复该漏洞。  
  
Wordpress.org上的下载数据统计显示，开发人员发布了最新更新后，约15万个网站安装了该插件，导致十几万WordPress站点仍然易受攻击。作为一般建议，网站所有人应当避免安装太多插件并弃用并非绝对需要的产品。此外，也可应用web应用防火墙，识别并阻止利用尝试。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[12年来最严重的 WordPress 漏洞，可大规模接管管理员权限](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521513&idx=1&sn=b60ee79ea2fbcfeaae560373faa7a2cf&scene=21#wechat_redirect)  
  
  
[WordPress 插件被安后门，用于发动供应链攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519884&idx=2&sn=394599c6e622c656ae34d0c38cb671fa&scene=21#wechat_redirect)  
  
  
[热门Wordpress 插件 LayerSlider 中存在严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519223&idx=2&sn=a927e2b6bd81218102ea07e2de3133d7&scene=21#wechat_redirect)  
  
  
[热门 WordPress 插件 Ultimate Member 中存在严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518957&idx=1&sn=8d096042c0c0ab672b2763c4be529085&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/google-oauth-flaw-lets-attackers-gain-access-to-abandoned-accounts/  
  
  
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
  
