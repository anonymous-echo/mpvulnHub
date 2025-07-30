#  速修复！开源防火墙软件pfSense 中存在多个漏洞   
THN  代码卫士   2023-12-18 18:18  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**开源的 Netgate pfSense 防火墙解决方案 pfSense 中存在多个漏洞，可被攻击者用于在可疑设备上执行任意命令。**  
  
  
这些问题和两个反射型XSS漏洞有关，其中一个是命令注入漏洞。安全研究员 Zeino-Mahmalat 表示，“局域网中的安全性通常更加薄弱，因为网络管理员信任自己的防火墙能够保护他们免遭远程攻击。潜在攻击者可利用已发现漏洞监控流量或者攻击局域网中的服务。”  
  
这些漏洞影响 pfSense CE 2.7.0及以下版本以及 pfSense Pluse 23.05.1及以下版本。攻击者可诱骗已认证的 pfSense 用户（如管理员用户）点击特殊构造的内含可激活命令注入漏洞的 XSS payload 的 URL。  
  
这些漏洞的概述如下：  
  
- CVE-2023-42325（CVSS评分5.4）：该XSS漏洞可导致远程攻击者通过 status_logs_filter_dynamic.php 页面的特殊构造的URL 获得权限。  
  
- CVE-2023-42327（CVSS评分5.4）：该XSS漏洞可导致远程攻击者通过 getserviceproviders.php页面特殊构造的URL获得权限。  
  
- CVE-2023-42326（CVSS评分8.8）：缺少验证可导致攻击者通过 interfaces_gif_edit.php和interfaces_gre_edit.php 组件的构造请求执行任意代码。  
  
  
  
反射型 XSS 攻击也被称为非持久性攻击，当攻击者向易受攻击的 web 应用传播恶意脚本时就会发生，之后该恶意脚本以 HTTP 响应方式返回并在受害者的web浏览器上执行。因此，这类攻击可通过内嵌在钓鱼信息或第三方网站中的构造链接的方式触发，如在评论区域或者以社交媒体帖子中的链接方式触发。在 pfSense 案例中，该攻击者可以受害者权限在防火墙中执行操作。  
  
Zeino-Mahmalat 表示，“由于 pfSense 流程以 root 身份运行，能够更改网络设置，因此攻击者可以 root 身份借该攻击执行任意系统命令。”  
  
自2023年7月3日收到漏洞报告后，pfSense CE 2.7.1和 pfSense Plus 23.09 已在上月发布修复了这些漏洞。  
  
几周前，Sonar 公司还详述了位于微软 VSCode 内置 npm 集成中的一个远程代码执行漏洞（CVE-2023-36742，CVSS评分7.8）。该漏洞可被用于执行任意命令。微软已在2023年9月发布的补丁星期二中修复该漏洞。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[多个高危漏洞可导致思科交换机和防火墙遭 DoS 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517453&idx=2&sn=251402ddfd4c8a150b8758f1c605b2af&chksm=ea94b467dde33d7195d23ecc995280d0ef6b19557e14a8330945c641004b75bea1871b2c82a6&scene=21#wechat_redirect)  
  
  
[合勤科技防火墙和VPN设备中存在多个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516588&idx=2&sn=9de12fd66aca0db1dd5cf6843cf5172b&chksm=ea94b0c6dde339d067936cdf6ad3806f1669be3d65022c613d8544726872d4dca7d3377e4a9f&scene=21#wechat_redirect)  
  
  
[速修复！Sophos 防火墙中的RCE 0day已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514074&idx=1&sn=849d683aa4c7d4ef90f9f8b7e1c2da9c&chksm=ea9486b0dde30fa63d6a04185ca12a12f4d497590f1bfaca5758906648d912976659d1b9d701&scene=21#wechat_redirect)  
  
  
[思科ASA防火墙中存在多个漏洞，可被用于供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513544&idx=2&sn=6c9886f2668674b71400b4eb1ccba93b&chksm=ea9484a2dde30db499db8f0b34a1e531a5db4571bb73988dfbc334e6409862d01a8840d94942&scene=21#wechat_redirect)  
  
  
[合勤科技修复四个高危漏洞，影响AP、API控制器和防火墙设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512001&idx=3&sn=e25d8213ca24152e4fe49ee900f53295&chksm=ea949eabdde317bdbdb50c88bc48a6238c3d4eb1a57347b38b9cfba3db4a24295bf78c1d8951&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/12/new-security-vulnerabilities-uncovered.html  
  
  
  
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
  
