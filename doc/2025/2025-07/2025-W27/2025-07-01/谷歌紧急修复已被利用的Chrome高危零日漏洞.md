> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324079&idx=3&sn=23330a41d753210c404f022f9a91115e

#  谷歌紧急修复已被利用的Chrome高危零日漏洞  
 FreeBuf   2025-07-01 11:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icgUvC6BMWGzibeXeQBrsXKkgLMUvq50uOOu24sLiaicyD2ibO4vHiaQH1wIiaKDlPyOibvrhfRGPCZpztXw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
谷歌在发现一个已被野外利用的高危零日漏洞（CVE-2025-6554）后，紧急为其Chrome浏览器的稳定版通道发布了更新。该漏洞被归类为V8 JavaScript引擎中的类型混淆漏洞，对Windows、macOS和Linux平台的用户构成严重威胁。  
  
  
**Part01**  
## 漏洞详情  
###   
  
CVE-2025-6554是Chrome核心渲染引擎V8 JavaScript引擎中的类型混淆漏洞。该漏洞由谷歌威胁分析小组（TAG）的Clément Lecigne于2025年6月25日发现，攻击者可通过诱使浏览器错误解析内存类型来执行任意代码——这种利用方法通常用于实现远程代码执行（RCE）。  
  
  
**Part02**  
### 风险等级  
  
  
零日漏洞——尤其是影响Chrome等浏览器的漏洞——是国家行为体、高级持续性威胁（APT）组织和以经济利益为目的的网络犯罪分子的主要目标。V8引擎中的类型混淆漏洞此前曾被用于"路过式下载"攻击、沙箱逃逸以及通过看似无害的网站投递恶意负载。  
  
  
**Part03**  
### 更新信息  
  
  
本次发布的补丁版本号为：Windows 版138.0.7204.96/.97、Mac 版138.0.7204.92/.93、Linux 版 138.0.7204.96，将在未来数日乃至数周内逐步推送。  
  
  
谷歌在公告中警告：已确认CVE-2025-6554漏洞的野外利用实例存在。  
鉴于该漏洞的敏感性及其潜在影响，在大多数用户获得保护前，完整技术细节仍将受限。  
  
  
**参考来源：**  
  
Google Patches Actively Exploited Chrome Zero-Day: CVE-2025-6554  
  
https://securityonline.info/google-patches-actively-exploited-chrome-zero-day-cve-2025-6554/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324007&idx=1&sn=b6bab0cab5bd97eeccb29752661d50e0&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
