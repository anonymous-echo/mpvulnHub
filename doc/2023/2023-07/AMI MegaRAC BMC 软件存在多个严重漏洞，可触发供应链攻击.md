#  AMI MegaRAC BMC 软件存在多个严重漏洞，可触发供应链攻击   
THN  代码卫士   2023-07-21 18:26  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**AMI MegaRAC Baseboard Management Controller (BMC) 软件中存在两个漏洞，可用于远程访问易受攻击的服务器并部署恶意软件。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQnaAVlFmR9PsiaXMTicaktriasVjlDPydC6SAKOshaNenrsHNkHTWic36z1R9FDPUCK2yw9d6GX6WK8g/640?wx_fmt=gif "")  
  
  
Eclypsium 公司的研究员 Vlad Babkin 和 Scott Scheferman 在报告中提到，“这些新漏洞的严重程度从高危到严重不等，包括未认证的远程代码执行和以超级用户权限越权访问设备等。攻击者如能访问 Redfish 远程管理接口即可利用这些漏洞，或从受陷主机操作系统实施利用。”  
  
更糟糕的是，这些漏洞可被武器化以释放持久的固件植入，这些植入免疫于操作系统重装和硬盘驱动替换、可使母板组件崩溃，通过高强度攻击造成物理损坏并触发无限重启循环。  
  
研究人员指出，“攻击者的关注点从面向用户的操作系统转到硬件和计算信任所依赖的更底层的嵌入式代码，使得攻陷更难以检测而修复的复杂度呈指数级增长。”  
  
此前，AMI MegaRAC BMC 受一系列漏洞影响，它们被统称为 “BMC&C”，其中一些在2022年12月披露（CVE-2022-40259、CVE-2022-40242和CVE-2022-2827）和2023年2月披露（CVE-2022-26872和CVE-2022-40258）。  
  
本次新披露的漏洞包括：  
  
- CVE-2023-34329（CVSS评分9.9）：经由HTTP标头欺骗的认证绕过漏洞  
  
- CVE-2023-34330（CVSS评分6.7）：经由动态Redfish 扩展接口的代码注入漏洞  
  
  
  
如被组合利用，则这两个漏洞的严重性评分为10.0分，可使攻击者绕过 Redfish 认证并通过最高权限在 BMC 芯片上执行任意代码。另外，这些漏洞可结合CVE-2022-40258 破解 BMC 芯片上管理员账户的密码。  
  
值得注意的是，这类攻击可导致安装恶意软件以执行长期的网络间谍活动，同时躲避安全软件的检测，更不用说执行横向移动甚至通过电源管理篡改技术如 PMFault 等破坏 CPU。  
  
研究人员表示，“这些漏洞为构成云计算基础的技术供应链带来严重风险。简言之，组件供应商中的漏洞影响很多硬件厂商，之后被传递给很多云服务。这些漏洞可为组织机构直接拥有的服务器和硬件以及支撑所使用云服务的硬件带来风险。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Google Cloud Build 漏洞可使黑客发动供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517101&idx=1&sn=b0c111a99bc956b2107431d6ebb95ab6&chksm=ea94b2c7dde33bd16109770cd4770a6f7f989e459557db59356249469c17b8d71240693faa1a&scene=21#wechat_redirect)  
  
  
[OWASP发布五维软件安全开发成熟度参考框架，提升软件供应链安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516985&idx=1&sn=60e84451958d6763e2ba2c83f327fc75&chksm=ea94b253dde33b45557d5a54bb61f09699af601db05850ba8c3f4335db4b9a64b2bf20d4624e&scene=21#wechat_redirect)  
  
  
[给CISO的软件供应链债务偿还指南](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516922&idx=1&sn=7bb2124f9575eccad6a3f365e7d35bc1&chksm=ea94b390dde33a86c7f79138b6cc01b6fc4e06225aab365c79a00050fb4c6065ae6445ef2668&scene=21#wechat_redirect)  
  
  
[新型供应链攻击利用被弃的 S3 存储桶分发恶意二进制](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516743&idx=2&sn=6d344438ea9093b12ca72ebcf003b2c6&chksm=ea94b32ddde33a3b6497d8f740e25f1fd7b2f4ab38d3fcbf7547cd1aed276f54bcaeb1e7f4c4&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/07/critical-flaws-in-ami-megarac-bmc.html  
  
  
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
  
