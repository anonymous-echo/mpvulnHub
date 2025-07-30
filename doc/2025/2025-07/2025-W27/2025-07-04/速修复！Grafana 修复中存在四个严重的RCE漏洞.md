> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523440&idx=2&sn=85a84a9138ea24b09e9ea0bcb9efe061

#  速修复！Grafana 修复中存在四个严重的RCE漏洞  
Ddos  代码卫士   2025-07-03 10:55  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRSylJK2k7H6mNqiaS2G6WRaeeK34cLHE6pe9VeOIHYiboAnKB0TMoayZCxFpHMLljzTnz9DnNuFiaqQ/640?wx_fmt=png "")  
  
  
  
专栏·供应链安全  
  
  
数字化时代，软件无处不在。软件如同社会中的“虚拟人”，已经成为支撑社会正常运转的最基本元素之一，软件的安全性问题也正在成为当今社会的根本性、基础性问题。  
  
  
随着软件产业的快速发展，软件供应链也越发复杂多元，复杂的软件供应链会引入一系列的安全问题，导致信息系统的整体安全防护难度越来越大。近年来，针对软件供应链的安全攻击事件一直呈快速增长态势，造成的危害也越来越严重。  
  
  
为此，我们推出“供应链安全”栏目。本栏目汇聚供应链安全资讯，分析供应链安全风险，提供缓解建议，为供应链安全保驾护航。  
  
  
注：以往发布的部分供应链安全相关内容，请见文末“推荐阅读”部分。  
  
  
  
**Grafana 实验室发布紧急安全公告，修复了影响两个关键组件 Grafana Image Renderer 插件和 Synthetic Monitoring Agent 的四个严重漏洞。这些漏洞源自组件中所使用的浏览器引擎 Chromium，带来严重的RCE威胁。**  
  
安全公告提到，“我们已发布Grafana Image Renderer 插件和 Synthetic Monitoring Agent更新，修复了四个严重漏洞（CVE-2025-5959、CVE-2025-6554、CVE-2025-6191和CVE-2025-6192）。”所有这些漏洞均与广泛使用的 JavaScript 引擎 Chromium V8 JavaScript 引擎有关。  
  
漏洞概述如下：  
  
- CVE-2025-5959：V8中的类型混淆漏洞，可导致攻击者通过构造的 HTML 在沙箱中执行任意代码。   
  
- CVE-2025-6554：另外一个类型混淆漏洞，可导致通过HTML payload 执行任意读/写操作。   
  
- CVE-2025-6191：整数溢出漏洞，可导致越界内存访问。  
  
- CVE-2025-6192：Chrome 的 Metrics 组件中的释放后使用漏洞，可导致堆损坏利用后果。  
  
  
  
这些漏洞如遭利用，可导致系统完全遭攻陷，CVSS v3.1评级为严重。这些漏洞影响如下版本：  
  
- Grafana Image Renderer < 3.12.9 版本  
  
- Synthetic Monitoring Agent < 0.38.3 版本  
  
  
  
该安全公告建议称，“建议运营 Grafana Image Renderer 插件或本地安装 Synthetic Monitoring Agent 的用户更新系统。”这些漏洞可通过构造的HTML页面遭利用，意味着即使在 Grafana 仪表盘中打开某些渲染过的内容，也可能导致攻击者趁虚而入。  
  
Grafana 发布了补丁和安装指令：  
  
Grafana Image Renderer：  
  
- 最低版本：3.12.9  
  
- 插件安装：grafana-cli 插件安装 grafana-image-renderer  
  
- Docker：docker拉取 grafana/grafana-image-renderer: 3.12.9  
  
  
  
Synthetic Monitoring Agent：  
  
- 最低版本：0.38.3  
  
- GitHub 下载：v0.38.3  
  
- Docker：docker拉取 grafana/synthetic-monitoring-agent:v0.38.3-browser  
  
  
  
关于补丁详情和安装文档，也可查看 Grafana 的官方插件页面和 Synthetic monitoring 设置指南。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
  
开源  
卫士试用地址：  
https://sast.qianxin.com/#/login  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[超4.6万个 Grafana 实例易受账户接管漏洞影响](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523297&idx=2&sn=ea60b085762fef54a56dea85a3150a40&scene=21#wechat_redirect)  
  
  
[Grafana 紧急提前修复已被公开的XSS 0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523102&idx=2&sn=3eb6fe83ca06d69dbd0a16a7c73dcde3&scene=21#wechat_redirect)  
  
  
[Grafana 提醒注意严重的认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516818&idx=4&sn=9a52564b1d6d8454dd34dce86019d266&scene=21#wechat_redirect)  
  
  
[Grafana 漏洞可导致管理员账户遭接管](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513049&idx=1&sn=31af4654137f918dc610ee51cf05649a&scene=21#wechat_redirect)  
  
  
[Grafana 中存在严重的未授权任意文件读取漏洞，已遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509616&idx=2&sn=27c5f9e457a2c2aa08753d9d0a67917e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://securityonline.info/four-critical-rce-flaws-found-in-grafana-plugins-via-chromium-patch-now/  
  
  
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
  
  
