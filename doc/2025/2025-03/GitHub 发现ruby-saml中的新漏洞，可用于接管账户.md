#  GitHub 发现ruby-saml中的新漏洞，可用于接管账户   
Ravie Lakshmanan  代码卫士   2025-03-14 18:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**开源库 ruby-saml 中存在两个高危漏洞，可导致恶意人员绕过SAML认证防护机制。**  
  
  
  
  
  
  
  
SAML 是基于XML的标记语言和开放标准，可用于在相关方之间交换认证和授权数据，启用单点登录 (SSO) 等特性，使个人通过单一的凭据集访问多个站点、服务和应用。这些漏洞是CVE-2025-25291和CVE-2025-25292，CVSS评分8.8，影响如下版本：  
  
- < 1.12.4  
  
- >= 1.13.0、< 1.18.0  
  
  
  
这些漏洞产生的原因在于REXML和Nokogiri 解析XML的方法不同，导致这两个解析器能够从同样的XML输入生成完全不同的文档结构。这个解析器的区别可导致攻击者能够执行“签名封装”攻击，从而导致认证绕过。这些漏洞已在 ruby-saml 1.12.4和1.18.0中修复。  
  
GitHub 在2024年11月发现并报送了该漏洞，表示它可被恶意人员滥用于执行账户接管攻击。GitHub 安全实验室的研究员 Peter Stöckli 表示，“拥有单一有效签名（通过验证SAML响应或目标组织机构断言的密钥实现）的攻击者能够利用该漏洞构建SAML断言并以任何用户的身份登录。”  
  
GitHub 还提到，该漏洞可看做哈希的验证与签名验证之间的“断联”，导致可通过解析器区别实施利用。  
  
Ruby-saml库1.12.4和1.18.0版本在处理压缩的SAML响应时，还修复了一个远程拒绝服务漏洞CVE-2025-25293（CVSS评分7.7）。建议用户更新至最新版本，以免遭受攻击。近六个月前，GitLab 和 ruby-saml 还修复了可导致认证绕过的另外一个严重漏洞（CVE-2024-45409，CVSS评分10）。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[GitHub 将为提升开源项目安全提供资金支持](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521564&idx=2&sn=d554c5607b52083d41be8c732115d490&scene=21#wechat_redirect)  
  
  
[GitHub Enterprise Server中存在严重漏洞，可越权访问实例](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521118&idx=1&sn=19780899ec9f4282e334e41a25f88aa3&scene=21#wechat_redirect)  
  
  
[GitHub 评论被滥用于推送密码窃取恶意软件](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520653&idx=2&sn=985604e150b5d7056b6fc8994a7e1bf0&scene=21#wechat_redirect)  
  
  
[GitHub Enterprise Server 中存在严重的认证漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520551&idx=2&sn=c7d2ba1175a4c946fe47679b75e3c64e&scene=21#wechat_redirect)  
  
  
[恶意 PyPI、NPM、Ruby 包正在瞄准 Mac 设备](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517570&idx=3&sn=e1e8c3f4da181c45574f67a713fa11bb&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/03/github-uncovers-new-ruby-saml.html  
  
  
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
  
