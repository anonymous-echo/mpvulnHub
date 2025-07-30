#  备份插件存在严重RCE漏洞，可导致WordPress网站遭接管   
 代码卫士   2023-12-13 17:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**作者：Elizabeth Montalbano**  
  
**编译：代码卫士**  
  
**WordPress 备份插件 Backup Migration 的下载次数已超过9万次，其中存在一个严重的RCE漏洞，可导致易受攻击的 WordPress 网站遭接管。这是又一起因建站平台插件漏洞造成的风险事件。**  
  
  
Nex Team 在 Backup Migration 插件中发现了一个 PHP 代码注入漏洞 CVE-2023-6553，CVSS评分9.8。该插件有助于创建备份站点。该插件的特性包括以及时的方式和通过多种配置调度备份，如精确定义应当位于备份中的具体文件和/或数据库、备份的存储位置以及名称等。  
  
Defiant 公司的资深 Web 应用漏洞研究员 Alex Thomas指出，“该漏洞可导致未认证的威胁行动者注入任意PHP代码，从而导致站点遭完全攻陷。” Wordfence 公司表示在研究报告完成前的仅24小时内就拦截了利用该漏洞的39起攻击活动。  
  
Nex Team 将该漏洞提交到 Wordfence 设立的漏洞奖励计划，后者通知了 Backup Migration 插件的创造者 BackupBliss，几小时后补丁发布。Wordfence 为此向研究员颁发2751美元的奖励。  
  
  
**未认证的、完全站点接管**  
  
  
  
  
  
WordPress CMS 上的网站数以亿计，该平台及其用户称为威胁行动者的庞大攻击面，因此常常是恶意攻击的目标。其中很多攻击通过插件安装恶意软件，轻松导致数千个甚至数百万个站点易遭攻击。攻击者还倾向于快速利用WordPress 中发现的漏洞。  
  
Wordfence 网站提到，该RCE漏洞是因为“攻击者能够控制传递给 include 的值，后续借此实现远程代码执行。这就使得未认证攻击者能够轻松在服务器上执行代码。”  
  
具体而言，Backup Migration 插件使用的/includes/backup-heart.php 文件的第118行试图包含来自 BMI_INCLUDES 目录中的bypasser.php。BMI_INCLUDES 目录由拼接 BMI_ROOT_DIR 和第64行商的 includes 字符串而定义；然而，BMI_ROOT_DIR 通过第62行商的 content-dir HTTP 标头定义，从而导致漏洞产生。这就意味着 BMI_ROOT_DIR 是用户可控状态。通过提交特殊构造的请求，威胁行动者可利用该漏洞包含任意的恶意PHP代码并在WordPress 实例安全上下文中的底层服务器上执行任意命令。  
  
  
**立即修复**  
  
  
  
  
  
所有1.3.7及以下版本的 Backup Migration 版本均可通过/includes/backup-heart.php 文件易受攻击。该漏洞已在1.3.8版本中修复。Wordfence 在文章中提到，“如果知道有人在网站上使用该插件，我们建议与之分享本安全公告，确保他们的站点是安全的，因为该漏洞可造成重大风险。”建议用户尽快更新至最新版本。  
  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[黑客利用WordPress 插件中的提权0day攻陷网站](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516908&idx=1&sn=3861a45ade1fc801daa3c767fef3f318&chksm=ea94b386dde33a90582ec8599b01780524bb88c9f1a2cd4cfd9874889611594313e5443e60b1&scene=21#wechat_redirect)  
  
  
[WordPress 紧急修复影响数百万网站 Jetpack 插件中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516649&idx=5&sn=3a673400f9a00b2b334fadfda1b0a8a9&chksm=ea94b083dde33995e9079edc64941b6bda561e4fbb1c4406e76ffcfb5423d723243494cbb5af&scene=21#wechat_redirect)  
  
  
[WordPress 热门插件中存在漏洞，200多万网站受影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516420&idx=2&sn=e419c137b012ee8e70e8514f7bf3a2e1&chksm=ea94b06edde339787fa928cc50927bb993d84cb037cf64c8f353c0b7afc9b6064576dddb5f44&scene=21#wechat_redirect)  
  
  
[PHP Everywhere 插件中存在严重RCE，影响数千个 WordPress 站点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510489&idx=3&sn=e7dbd1c73e937e2dbf783f1afa6342e0&chksm=ea9498b3dde311a55ff3cf2243b100fde04a60f7793ad2161b221fe028886010921f3971eb0c&scene=21#wechat_redirect)  
  
  
[黑客在数十个 WordPress 插件和主题中插入秘密后门，可发动供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510263&idx=1&sn=de29839373754b8dbcb3ea4b4bc99067&chksm=ea94999ddde3108b0692e93d7baf65159c5fbebd6a40fe02d124421d7a662caced29c664ccdd&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.darkreading.com/cloud-security/critical-wordpress-plugin-rce-bug-exposes-websites-takeover  
  
  
题图：  
Pixabay  
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
  
