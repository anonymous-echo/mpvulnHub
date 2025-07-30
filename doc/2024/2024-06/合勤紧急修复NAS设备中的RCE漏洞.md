#  合勤紧急修复NAS设备中的RCE漏洞   
Bill Toulas  代码卫士   2024-06-05 17:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**合勤 (Zyxel) 网络公司紧急发布安全更新，修复了影响已达生命周期的老旧NAS 设备中的三个严重漏洞。**  
  
这三个漏洞影响运行固件版本5.21 (AAZF.16) Co及更早版本的NAS326以及影响5.21 (ABAG.13) Co及更早版本的NAS542设备。这三个严重漏洞可使攻击者执行命令注入和远程代码执行攻击。不过其中两个可导致提权和信息泄露的漏洞并未在到达生命周期的产品中修复。  
  
Outpost24公司的安全研究员 Timothy Hjort 发现并将五个漏洞报送给合勤公司。目前，研究人员已发布详细技术分析和 PoC 利用。在这五个漏洞中，合勤仅修复了CVE-2024-29972、CVE-2023-29973和CVE-2024-29974三个漏洞。  
  
这五个漏洞如下：  
  
- **CVE-2024-29972****：**位于CGI程序 (“remote_help-cgi”) 中的命令注入缺陷，可导致未认证攻击者发送特殊构造的 HTTP POST 请求，使用具有 root 权限的 NsaRescueAngel 后门账户执行OS命令。  
  
- **CVE-2024-29973****：**位于 “setCookie” 参数中的命令注入漏洞，导致攻击者发送特殊构造的 HTTP POST请求，执行OS命令。  
  
- **CVE-2024-29974****：**位于CGI程序 (“file_upload-cgi”)中的远程代码执行漏洞，可导致未认证攻击者在设备上上传恶意配置文件。  
  
- **CVE-2024-29975****：**位于SUID可执行二进制中的权限管理不当漏洞，可导致认证的具有管理员权限的本地攻击者以 “root”用户身份执行系统命令（未修复）。  
  
- **CVE-2024-29976****：**“show_allsessions”命令中的权限管理不当漏洞，可导致认证攻击者获得会话信息，包括活跃的管理员cookie等（未修复）。  
  
  
  
尽管这两个 NAS 设备机型都已在2023年12月31日达到支持周期，但合勤在5.21 (AAZF.17)Co 为 NAS326以及在5.21(ABAG.14)Co 为NAS542机型修复了这三个严重漏洞。合勤发布安全公告表示，“鉴于CVE-2024-29972、CVE-2024-29973和CVE-2024-29974漏洞的严重性，而尽管这些产品已达漏洞支持周期，但合勤 公司已向客户发布补丁。”  
  
合勤表示并未发现漏洞遭在野利用的迹象。不过，由于已存在公开的 PoC 利用，因此用户应尽快应用这些安全更新。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[合勤科技修复防火墙产品中的远程代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518947&idx=2&sn=8758a5f5ef83a075fb61fbed63159da1&chksm=ea94bb89dde3329f7456dbac7c02de7915e34069451108f060250d64c23c6f9145d80e39bcc4&scene=21#wechat_redirect)  
  
  
[合勤提醒注意 NAS 设备中的多个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518251&idx=2&sn=e34aa255b21da7352d4cee7ee282c3a2&chksm=ea94b941dde330570cdee756bdd509db2cfbd20562651fa3418a04f3424d1d19ff98455b0ee8&scene=21#wechat_redirect)  
  
  
[合勤科技修复NAS 设备中的高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516649&idx=2&sn=8568497e673e6061401b953a0bb37e2d&chksm=ea94b083dde3399587e9f570cb506e4f4d17d2f23280a147343bc96a5a1c55eaa427de1dffb0&scene=21#wechat_redirect)  
  
  
[合勤科技防火墙和VPN设备中存在多个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516588&idx=2&sn=9de12fd66aca0db1dd5cf6843cf5172b&chksm=ea94b0c6dde339d067936cdf6ad3806f1669be3d65022c613d8544726872d4dca7d3377e4a9f&scene=21#wechat_redirect)  
  
  
[刚刚，合勤科技发布NAS新固件，修复严重的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513843&idx=2&sn=8542b0597bb31128891e9f651a8afc17&chksm=ea948799dde30e8fec2983d236de83edbc94c48dc8271c57d4c59d10286c37ff6d303542a054&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/zyxel-issues-emergency-rce-patch-for-end-of-life-nas-devices/  
  
  
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
  
