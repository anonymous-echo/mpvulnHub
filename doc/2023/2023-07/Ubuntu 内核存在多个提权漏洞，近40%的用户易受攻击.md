#  Ubuntu 内核存在多个提权漏洞，近40%的用户易受攻击   
Bill Toulas  代码卫士   2023-07-27 17:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Ubuntu 内核中存在两个 Linux 漏洞，可导致低权限的本地用户在大量设备上提权。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTC64dm9d8xrebfJjKAGtg3jOfWicmLF9ia1P6ay6mnkWmbBMIdwK0HO9d7lgxjJ0UW60CcaYnic4GIQ/640?wx_fmt=gif "")  
  
  
Ubuntu 是使用最广泛的 Linux 发行版本之一，在美国尤为受欢迎，用户大约超过4000万名。近日，Wiz 公司的研究人员 S. Tzadik 和 S. Tamari 从该操作系统中发现了两个漏洞CVE-2023-32629和CVE-2023-2640，影响约40%的 Ubuntu 用户。  
  
CVE-2023-2640是位于 Ubuntu Linux 内核中的高危漏洞（CVSS v3评分7.8），是由许可检查不当造成的，可导致本地攻击者获得提权。CVE-2023-32629是位于 Linux 内核内存管理子系统中的一个中危漏洞（CVSS v3 评分5.4），访问 VMAs 的一个竞争条件可导致释放后使用后果，从而导致本地攻击者执行任意代码。  
  
这两名分析师是发现将 OverlayFS 模块实现到 Linux 内核中存在差异时找到的这些漏洞。OverlayFS 是一种联合挂载文件系统实现，由于可允许通过用户命名空间实现低权限访问且受易遭利用漏洞影响，因此过去遭到很多次攻击。Ubuntu 是使用 OverlayFS 的发行版本之一，在2018年在 OverlayFS 模块中实现多种总体是安全的自定义变化。然而，2019年和2022年，Linux 内核项目自行修改该模块，而这种修改和 Ubuntu 的变更之间是冲突的。最近大量发行版本采用了包含这些变更的代码，而这种冲突引入了这些漏洞。遗憾的是，利用风险非常高，因为这两个漏洞的 PoC 已公布很久。  
  
研究人员提醒称，“这两个漏洞都是 Ubuntu 内核独有的，因为它们源自 Ubuntu 对 OverlayFS 模块的单独修改。OverlayFS 之前的漏洞无需任何变动，因此这些漏洞的武器化利用已公开可用。”  
  
应该注意的是，这两个漏洞仅影响 Ubuntu，其它 Linux 发行版本如 Ubuntu 分叉并未使用 OverlayFS 模块的自定义修改，因此应该是安全的。  
  
Ubuntu 已发布关于这些漏洞的安全公告，Ubuntu Linux 内核最新版本还修复了其它6个漏洞，并已发布更新。建议不了解如何卸载并激活第三方内核模块的用户通过包管理器进行更新，这种更新方式应该能够覆盖到所有依赖和安装后的配置。更新安装后需要重启才能在 Ubuntu 上应用该 Linux 内核更新。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Citrix 修复 Ubuntu 版本安全访问客户端中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517034&idx=4&sn=6e2b7be2533c1e454539a3b4905483c7&chksm=ea94b200dde33b16f46f5c52b43bc116d9a9ed99bf381bbe9dbd8d1b3902ca57cb785c81a283&scene=21#wechat_redirect)  
  
  
[利用AccountsService 漏洞获得Ubuntu系统的root权限](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509684&idx=2&sn=8b87de3d9f2e46bbf100f6ab09606d63&chksm=ea9497dedde31ec8fb0ea2eebaaf2419a8e3ef5166bb5fbcbd15c5bad27af32fc893618b99b3&scene=21#wechat_redirect)  
  
  
[Ubuntu 源代码还安全吗？Canonical GitHub 账户遭攻陷](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490378&idx=2&sn=86c01190b324035b8d6bfe8423e4af91&chksm=ea972a20dde0a336e8f66c90a036933cb4e1c3f9f633495b3a06162d270ac4b8849e1887157e&scene=21#wechat_redirect)  
  
  
[Ubuntu Snap 商店中出现恶意包](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247487110&idx=4&sn=a449ac176ccd91328101a4916ba3f82a&chksm=ea973fecdde0b6fa50c9ac0f9624a388174f7bea5cb00ab49c2d03a33cbbbcd3c0ad012d189f&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/almost-40-percent-of-ubuntu-users-vulnerable-to-new-privilege-elevation-flaws/  
  
  
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
  
