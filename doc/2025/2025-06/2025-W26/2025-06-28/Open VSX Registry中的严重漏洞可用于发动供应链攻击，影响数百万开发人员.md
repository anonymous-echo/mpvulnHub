> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523394&idx=2&sn=d589b77eb9be15ec2ad03480d601ade3

#  Open VSX Registry中的严重漏洞可用于发动供应链攻击，影响数百万开发人员  
Ravie Lakshmanan  代码卫士   2025-06-27 10:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRSylJK2k7H6mNqiaS2G6WRaeeK34cLHE6pe9VeOIHYiboAnKB0TMoayZCxFpHMLljzTnz9DnNuFiaqQ/640?wx_fmt=png "")  
  
  
  
专栏·供应链安全  
  
  
数字化时代，软件无处不在。软件如同社会中的“虚拟人”，已经成为支撑社会正常运转的最基本元素之一，软件的安全性问题也正在成为当今社会的根本性、基础性问题。  
  
  
随着软件产业的快速发展，软件供应链也越发复杂多元，复杂的软件供应链会引入一系列的安全问题，导致信息系统的整体安全防护难度越来越大。近年来，针对软件供应链的安全攻击事件一直呈快速增长态势，造成的危害也越来越严重。  
  
  
为此，我们推出“供应链安全”栏目。本栏目汇聚供应链安全资讯，分析供应链安全风险，提供缓解建议，为供应链安全保驾护航。  
  
  
注：以往发布的部分供应链安全相关内容，请见文末“推荐阅读”部分。  
  
  
  
**网络安全研究人员披露了位于 Open VSX Registry  (“open-vsx.org”) 中的一个严重漏洞，如遭成功利用，本可导致攻击者控制整个Visual Studio Code 扩展市场，造成严重的供应链风险。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTA3rktn5u4X8ibnvVwA9VFKvd0pSS5CHeyqB6Alk1ibnwyJNhzoiabFZJRSlISXMm4nuceGMTSb9ibfw/640?wx_fmt=png&from=appmsg "")  
  
  
Koi Security 公司的研究员 Oren Yomtov 表示，“该漏洞可使攻击者完全控制整个扩展市场，从而完全控制数百万开发者机器。恶意人员可利用一个 CI漏洞，将恶意更新发布到 Open VSX 上的每个扩展中。” 研究人员在2025年5月4日负责任披露该漏洞，项目维护人员已发布多轮修复方案，并于6月25日部署。  
  
Open VSX Registry 是一款开源项目，也是 Visual Studio Marketplace的替代品，由 Eclipse 基金会维护。多款代码编辑器如 Cursor、Windsurf、Google Cloud Shell 编辑器、Gitpod 等已在服务中集成该项目。Yomtov 表示，“这种大规模的部署意味着攻陷 Open VSX 将是供应链的噩梦。”   
  
该漏洞的根因在于 publish-extensions 仓库，该仓库包含将开源 VS Code 扩展发布到 open-vsx.org 中的脚本。开发人员提交拉取请求将扩展添加到该仓库的 extensions.json 文件中，从而请求自动发布他们的扩展，该请求在获得批准并合并后生效。在后台这一过程通过GitHub Actions 工作流实现。该工作流每天在世界标准时间凌晨03:03运行一次，读取JSON文件中用逗号分隔的扩展列表，使用 vsce npm 包发布到该注册表中。Yomtov 表示，“该工作流以包括@open-vsx 服务账号的一个机密令牌 (OVSX_PAT) 在内的特权凭据运行，能够在市场中发布（或覆盖）任何扩展。从理论上来讲，只有受信任的代码才应该能过看到该令牌。该漏洞的根因在于 npm install 在提供 OVSX_PAT 环境变量访问权限的同时，运行所有自动发布扩展及其依赖的任意构建脚本。”这意味着，攻击者很有可能获得 @open-vsx 账号令牌的访问权限，获得对 Open VSX Registry 的特权访问权限，并能够发布新的扩展以及篡改现有扩展插入恶意代码。  
  
针对由扩展带来的风险，MITRE于2025年4月在 ATT&CK 框架中推出了新的“IDE扩展”技术，表示该技术可被恶意人员滥用于建立对受害者系统的永久访问权限。  
  
Yomtov 表示，“每个市场项目都是一个潜在的后门。它们是具有特权访问权限的未经审查的软件依赖，而且它们应该获得来自PyPI、npm、Huggingface或GitHub 上的任何包的同样的尽职调查。如未被检查，它们会创建一个不断延伸的不可见的供应链，遭越来越多的攻击利用。”  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
  
开源  
卫士试用地址：  
https://sast.qianxin.com/#/login  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[60+ GitHub 仓库被用于软件供应链攻击中](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523354&idx=1&sn=d244bf059793bcbf601d864f0f7a0327&scene=21#wechat_redirect)  
  
  
[谷歌 Gerrit 代码平台漏洞可用于供应链攻击，18个谷歌项目受影响](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523322&idx=1&sn=33329d3ec49e0f180be0dcedb8cd70a4&scene=21#wechat_redirect)  
  
  
[谷歌修复代码测试工具Bazel 中的严重供应链漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518821&idx=1&sn=8a1a67b87d1bbad6e1c80390fe7c1c61&scene=21#wechat_redirect)  
  
  
[谷歌推出开源计划GUAC，保护软件供应链安全](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514298&idx=2&sn=5971ca324b4d2fe15146eefac3a7192c&scene=21#wechat_redirect)  
  
  
[NPM软件供应链攻击传播恶意软件](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523234&idx=2&sn=ac4e0656fd04218349d356761af176dd&scene=21#wechat_redirect)  
  
  
[隐秘的 npm 供应链攻击：误植域名导致RCE和数据破坏](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523167&idx=2&sn=4249c8e9e0dace01810c665eda52c421&scene=21#wechat_redirect)  
  
  
[在线阅读版：《2024中国软件供应链安全分析报告》全文](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520484&idx=1&sn=8a845b39720a318c297075e98f5fe5e0&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://cybersecuritynews.com/cisco-anyconnect-vpn-server-vulnerability/  
  
  
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
  
  
