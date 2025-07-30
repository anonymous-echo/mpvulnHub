#  Craft CMS RCE利用链用于窃取数据   
Lawrence Abrams  代码卫士   2025-04-27 10:12  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Orange Cyberdefense 公司提到，Craft CMS 中存在两个漏洞，可用于攻陷服务器和窃取数据。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTpOt1icw0pRNL9tiaHgGmwcSnusl6tVwwbgeKicqKoNdwfeweDHfuOibODsX207pwMhsH2p6iaGpArZeQ/640?wx_fmt=png&from=appmsg "")  
  
  
这两个漏洞是由 Orange Cyberdefense 公司的部门CSIRT在调查一台受陷服务器时发现的。这两个漏洞是CVE-2025-32432和CVE-2024-58136，前一个是位于Craft CMS中的RCE漏洞，而后者是位于Craft CMS所用的Yii 框架中的输入验证漏洞。  
  
Orange Cyberdefense 的道德黑客团队SensePost 报道称，威胁行动者组合利用这两个漏洞攻陷服务器并上传了一个PHP 文件管理器。攻击始于 CVE-2025-32432的利用，该漏洞可使攻击者发送包含 “return URL” 的特殊构造请求作为参数并保存在一个PHP 会话文件中。该会话名称作为HTTP请求响应的一部分发送给访客。  
  
该攻击的第二个阶段涉及 Yii 框架中的一个漏洞CVE-2024-58136。攻击者为利用该漏洞，发送一个恶意 JSON payload，导致该会话文件中的PHP代码在服务器上执行。这就可使攻击者在服务器上安装一个基于PHP的文件管理器，进一步攻陷系统。  
  
Orange 公司表示，他们还看到了其它的攻陷步骤，包括更多的后门payload 和数据提取。后续将发布更多利用后活动的详情。Yii 开发人员最终在4月9日发布的 Yii 2.0.52 版本中修复了该漏洞。  
  
Craft CMS 还在4月10日，在版本3.9.15、4.14.15和5.6.17中修复了CVE-2025-32432。虽然研究人员并未将 Yii 更新至最新版本，但表示攻击链仍然是被修复状态。Orange 公司表示，“今天，2.0.51（易受攻击）仍然默认位于 Craft 上，然而，有了CVE-2025-32432修复方案，Yii 问题现在仍然无法被触发。”  
  
Craft CMS 建议管理员如认为其站点已被攻陷，则执行如下步骤：  
  
- 刷新安全密钥，以防密钥已被捕获。用户可运行 php craft setup/security-key 命令并将更新后的环境变量 CRAFT_SECURITY_KEY 复制到所有的生产环境。  
  
- 如果有其它密钥存储为环境变量（如S3或Stripe），也需要刷新。  
  
- 更改数据库凭据。  
  
- 出于谨慎考虑，强制所有用户重置密码，以免数据库受陷。可通过运行 php craft resave/users— 将 passwordResetRequired—设置为 “fn()=>true”。  
  
  
  
如需了解完整的妥协指标，包括IP地址和文件名称，可查看 SensePost 发布的报告附录。  
  
2月，CISA还表示，Craft CMS 4和5中的代码执行 (RCE) 漏洞已遭在野利用。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CISA：Craft CMS代码注入漏洞已遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522334&idx=3&sn=f5c15f723d85e58e935d673891c323e3&scene=21#wechat_redirect)  
  
  
[PHPFusion 开源 CMS 中存在严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517570&idx=2&sn=7f19eccf19674dfcdf5f6515082f6989&scene=21#wechat_redirect)  
  
  
[开源CMS TYPO3中存在XSS漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513988&idx=2&sn=d8e2aa2199ecfa383521908c1073c29b&scene=21#wechat_redirect)  
  
  
[开源的dotCMS 内容管理软件中存在严重的RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511649&idx=2&sn=b8446991d9e5831092d721d0b28041e9&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/craft-cms-rce-exploit-chain-used-in-zero-day-attacks-to-steal-data/  
  
  
  
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
  
