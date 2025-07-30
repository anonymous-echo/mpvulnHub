#  CISA提醒修复Zoho ManageEngine RCE漏洞   
Ionut Arghire  代码卫士   2022-09-27 18:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**摘要**  
  
本周四，美国网络安全和基础设施安全局 (CISA) 提醒称，网络攻击活动正在利用最近修复的一个Zoho ManageEngine 漏洞 (CVE-2022-35405)。  
  
Zoho 公司在2014年收购企业IT软件ManageEngine，后者未身份和访问、端点、企业服务、安全信息和实践以及IT运营提供管理能力。  
  
CVE-2022-35405的CVSS评分为9.8，是一个远程代码执行漏洞，影响 ManageEngine Password Manager Pro 12101之前、ManageEngine PAM360 5510之前以及ManageEngine Access Manager Plus 4303之前的版本。  
  
攻击者无需验证即可利用位于ManageEngine Password Manager Pro和ManageEngine PAM360中的漏洞，不过需要认证才可利用位于ManageEngine Access Manager Plus中的漏洞。  
  
Zoho 公司已在今年6月份发布补丁修复该漏洞，当时它提醒称网络已存在相关的 PoC 验证，“上述漏洞的 PoC 利用已公开。我们强烈建议客户立即升级 Password Manager Pro、PAM360和Access Manager Plus实例”。  
  
发现该漏洞的研究员在本月初发布博客文章，说明了自己的研究成果。  
  
本周四，CISA将该漏洞增加到“已知已遭利用漏洞”分类列表中，表示已发现遭活跃利用的证据。CISA表示位于该列表中的漏洞一般被用于获得初始访问权限，表示联邦机构应当在10月13日之前应用补丁。  
  
按照绑定运营指令 (BOD) 22-01的要求，联邦机构需要在各自环境中解决这些已知漏洞，不过CISA提到所有组织机构均应查看该列表并优先及时修复。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Zoho 修复Desktop Central 中的又一个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510205&idx=2&sn=fbb87a877e97e34fb152bc81962d6de5&chksm=ea9499d7dde310c1fb599ae9bb9de17c808e9fd50a2a19f536a14bc1c30977d4228d22f050be&scene=21#wechat_redirect)  
  
  
[Zoho：尽快修复已遭利用的 ManageEngine 严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509574&idx=1&sn=4087ce0dae2fc5f7466509361bc75784&chksm=ea94972cdde31e3a15e2a7fe2d009f93789638cd6b891a8e91b22cbee7676592795119f0ebd8&scene=21#wechat_redirect)  
  
  
[速修复！CISA警告称 Zoho 服务器0day已遭在野利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507788&idx=1&sn=e214c47f6b9386fb54d17a76c106edd5&chksm=ea94ee26dde36730944db8a129312db47ea0185813d6ca999a70d4e9a4103cef63e89a270e02&scene=21#wechat_redirect)  
  
  
[FireEye 红队失窃工具大揭秘之：分析复现 Zoho 任意文件上传漏洞(CVE-2020-8394)](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247499209&idx=1&sn=c75109e0d988fda2f938bd1e60541bf0&chksm=ea94cca3dde345b520c82baba98a3a5296bf5e3276c3acdcc7e7d682c32f66864d2b938c322b&scene=21#wechat_redirect)  
  
  
[FireEye红队失窃工具大揭秘之：分析复现Zoho ManageEngine RCE (CVE-2020-10189)](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247499078&idx=1&sn=2d07caa663bb17250a5d4d858c1fcd71&chksm=ea94cc2cdde3453a3afe795878114bb9cd5177d68024846d7b633a0fa8ad80611e92c4931ecd&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/cisa-warns-zoho-manageengine-rce-vulnerability-exploitation  
  
  
题图：  
Pixabay License  
‍  
  
  
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
