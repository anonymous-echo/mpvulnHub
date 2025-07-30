> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523347&idx=2&sn=b6f02b127ba49b7fa05eec183cb4108a

#  Sitcore XP中的硬编码密码 “b” 导致企业系统易受RCE攻击  
Ravie Lakshmanan  代码卫士   2025-06-20 10:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**网络安全研究员披露了热门 Sitecore Experience Platform (XP) 中的三个漏洞，它们可组合用于实现预认证远程代码执行。**  
  
Sitecore XP是一款企业级软件，为用户提供内容管理、数字化营销以及分析和报告服务。这三个漏洞简述如下：  
  
- CVE-2025-34509（CVSS 8.2）：使用硬编码凭据。  
  
- CVE-2025-34510（CVSS 8.8）：通过路径遍历实现认证后远程代码执行。  
  
- CVE-2025-34511（CVSS 8.8）：通过 Sitecore PowerShell Extension 实现认证后远程代码执行。  
  
  
  
watchTowr Labs 的研究员Piotr Bazydlo 表示，默认的用户账号 “sitecore\ServicesAPI” 的密码是一位数且为硬编码的 “b”。Sitecore 在文档中建议客户更改默认的用户账号凭据。  
  
虽然用户在 Sitecore 中并没有被分配角色和权限，但研究人员发现攻击者仍然能够利用他们的凭据，以 “sitecore\ServicesAPI” 的身份登录到API 端点 “/sitecore/admin” 并获得有效的会话cookie。Bazydlo 解释称，“虽然由于 ServicesAPI 没有被分配角色，我们无法访问 ‘Sitecore Applications’（定义大部分功能），但我们仍能够（1）访问其它大量API，以及（2）通过IIS授权规则并直接访问一些端点。” 攻击者可通过一个zip slip漏洞执行远程代码，从而通过端点“/sitecore/shell/Applications/Dialogs/Upload/Upload2.aspx” 上传一个特殊构造的的 ZIP 文件，导致该文档的内容（如 web shell）被写入 webroot 目录。  
  
完整的操作顺序如下：  
  
- 认证为 “sitecore\ServicesAPI” 用户  
  
- 访问 Upload2.aspx  
  
- 上传一个 ZIP 文件，其中包含一个名为 /\/../<web_shell> 的 web shell。  
  
- 当弹出时，检查解压缩选项并完成上传。  
  
- 访问 web shell。  
  
  
  
第三个漏洞与 PowerShell Extensions 中的一个不受限的文件上传漏洞有关，可被用作 “sitecore\ServicesAPI” 用户，通过端点 “/sitecore%20modules/Shell/PowerShell/UploadFile/PowerShellUploadFile2.aspx” 实现远程代码执行。  
  
WatchTowr 提到，该硬编码密码原则 Sitecore 安装程序中，它导入 ServicesAPI 密码设为 “b” 的预配置用户数据库，这一变化从10.1版本起开始生效。这意味着只有当用户使用10.1版本及以上的安装程序安装 Sitecore 时，该利用链才起作用。如果用户最开始运行的版本是10.1而之后升级至更新的易受攻击版本，假设旧的数据库已迁移而内嵌在安装包中的数据库未迁移，则用户可能并不受影响。  
  
鉴于Sitecore XP 中此前漏洞 (CVE-2019-9874和CVE-2019-9875) 曾遭在野利用，因此用户应应用最新补丁。watchTowr 公司的首席执行官兼创始人 Benjamin Harris 提到，“默认情况下，Sitecore 的近期版本中用户的硬编码密码是 ‘b’。现在都已经2025年了，竟然还有这种糟糕的情况。Sitecore 部署于数千个环境中，包括银行、航空公司和全球企业，因此影响范围甚广。而且这种影响并非仅存在于理论层面：我们运行了端对端的完整利用链。如果你正在运行 Sitecore，那么情况不会变得更糟糕了：在攻击者逆向修复方案前，立即修改凭据并打补丁。”  
  
Sitecore公司的一名发言人表示，“我们注意到 watchTowr 最近在我们的软件中发现多个漏洞，我们正在与他们积极协作解决该漏洞，并发布一份知识库文章，详述了补丁和修复步骤。”该公司还提到已在2024年12月修复了 watchTowr 在2025年2月发现的漏洞CVE-2025-27218。该公司提到，“我们的客户支持团队已积极与受影响客户沟通这些更新。所有受影响的 SaaS 产品已得到修复，我们强烈建议受影响的本地客户立即应用补丁。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[BeyondTrust：注意远程支持软件中的预认证RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523333&idx=1&sn=7293c7dd1145ab18fd71d834ad208fe0&scene=21#wechat_redirect)  
  
  
[Veeam RCE漏洞导致域用户入侵备份服务器](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523322&idx=2&sn=347204929358f8a4c82b2634e62774cd&scene=21#wechat_redirect)  
  
  
[隐秘的 npm 供应链攻击：误植域名导致RCE和数据破坏](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523167&idx=2&sn=4249c8e9e0dace01810c665eda52c421&scene=21#wechat_redirect)  
  
  
[DragonForce 勒索团伙瞄准MSP，发动供应链攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523133&idx=1&sn=bf9dda6dcef75f6de012aa77866b6072&scene=21#wechat_redirect)  
  
  
[Setuptools 漏洞导致数百万 Python 用户易受RCE攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523092&idx=1&sn=53658193138b944b76bad2de5c9801f5&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/06/hard-coded-b-password-in-sitecore-xp.html  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
