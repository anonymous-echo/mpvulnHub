#  微软：热门源代码管理平台 Perforce Helix Core Server 中存在RCE漏洞   
Bill Toulas  代码卫士   2023-12-19 17:47  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**微软在游戏、政府、军队和技术行业都在使用的源代码管理平台 Perforce Helix Core Server 上发现了四个漏洞，其中一个是严重等级。**  
  
  
微软公司的分析师对该平台的一次安全审计中发现了这些漏洞，并在2023年8月告知Perforce 公司。微软的游戏开发制作室使用该源代码管理平台。  
  
尽管微软表示尚未看到这些漏洞遭在野利用的情况，但建议用户升级至在2023年11月7日发布的版本2023.1/2513900。  
  
  
漏洞简介  
  
  
这四个漏洞主要是拒绝服务 (DoS) 问题，其中最严重的可导致未认证攻击者以 LocalSystem 的权限实现任意远程代码执行后果。  
  
这四个漏洞是：  
  
- CVE-2023-5759（CVSS评分7.5）：可通过 RPC 标头滥用导致未认证 DoS。  
  
- CVE-2023-45849（CVSS评分9.8）：以 LocalSystem 权限实现未认证的 RCE。  
  
- CVE-2023-35767（CVSS评分7.5）：通过远程命令实现未认证的DoS。  
  
- CVE-2023-45319（CVSS评分7.5）：通过远程命令实现未认证的DoS。  
  
  
  
上述最严重的漏洞是CVE-2023-45849，可导致未认证攻击者以 “LocalSystem” 的身份执行代码，而该权限是未系统函数保留的高权限 Windows OS 账户。该账户级别可访问本地资源和系统文件、修改注册表设置等。  
  
该漏洞是因为该服务器对 user-bgtask RPC 命令处理不当造成的。在默认配置下，Perforce Server 允许未认证攻击者远程以 LocalSystem 身份执行任意命令如 PowerShell 脚本等。  
  
攻击者可利用CVE-2023-45849 安装后门、访问敏感信息、创建或修改系统设置并可能完全控制运行易受攻击的 Perforce Server 的系统。  
  
余下的三个漏洞严重性较低，可导致DoS攻击，但仍然可导致运营中断，从而在大型部署中造成重大经济损失。  
  
  
防护建议  
  
  
除了从厂商的下载门户下载最新版本的 Helix Core 外，微软建议采取如下措施：  
  
- 定期更新第三方软件  
  
- 限制访问权限，如使用VPN或IP白名单  
  
- 记录对 Perforce Server 的所有访问  
  
- 为IT和安全团队设置崩溃报警  
  
- 通过网络分段防止安全事件  
  
  
  
此外，建议采取官方安全指南提供的建议。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[恶意npm包窃取源代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517509&idx=3&sn=d99a52344f095e58bed171f09aebf4c9&chksm=ea94b42fdde33d393c1c53db62a00f9cce11bbec2dcf5a80de4d5f89da1b078789e0e1d63014&scene=21#wechat_redirect)  
  
  
[推特源代码在GitHub 泄漏三个月之久](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516064&idx=3&sn=1ee10d19e2269fa8cd24675a1e68c64e&chksm=ea948ecadde307dc4777959fc9483de5297fb419a29d3f05ab2d53e1d69e2929d4569cae5d0b&scene=21#wechat_redirect)  
  
  
[GoDaddy 源代码被盗，遭多年持续攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515674&idx=3&sn=05b7c5d5d66547fe3eea1e4f74014282&chksm=ea948f70dde306663e145b649cac0f572cd90b81eef0cba19213e7bcea90a6b433c606a1f1e2&scene=21#wechat_redirect)  
  
  
[备份插件存在严重RCE漏洞，可导致WordPress网站遭接管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518349&idx=2&sn=da5a15622c08723ed8cacf81f9a2dd55&chksm=ea94b9e7dde330f1ebb50e99491cbc925e6e932730363f189179878a4dc2b3a4ccb480badb86&scene=21#wechat_redirect)  
  
  
[CISA 提醒注意已遭活跃利用的 Juniper 预认证 RCE 利用链](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518122&idx=1&sn=d6b5a20e45ee8897ed249a7bdde21ebb&chksm=ea94b6c0dde33fd6d3d93c996ad772d6f9f1d4744294db1c793f9f4cd69798f6515ac436fa3c&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/microsoft-discovers-critical-rce-flaw-in-perforce-helix-core-server/  
  
  
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
  
