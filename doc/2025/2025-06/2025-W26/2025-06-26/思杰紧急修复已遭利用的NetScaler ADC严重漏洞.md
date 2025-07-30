> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523387&idx=1&sn=d337384a0eacef330ea1c9beaedf7937

#  思杰紧急修复已遭利用的NetScaler ADC严重漏洞  
Ravie Lakshmanan  代码卫士   2025-06-26 10:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**思杰 (Citrix) 发布安全更新，修复了已遭利用的影响 NetScaler ADC 的严重漏洞CVE-2025-6543，CVSS v4评分9.2。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSZVXfR0ju8yz6BT5GKYrGZQFmylymiaH907l0Vo0Qd6A1Da53m4d04nR1iahibpG6jrqQNI4bJqzasQ/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞是一个内存溢出漏洞，可导致非预期的控制流和拒绝服务。然而，成功利用该漏洞要求将设备配置为网关（VPN 虚拟服务器、ICA Proxy、CVPN、RDP Proxy）或者AAA 虚拟服务器。  
  
该漏洞影响如下版本：  
  
- NetScaler ADC 和 NetScaler Gateway 14.1-47.46 之前的14.1 版本  
  
- NetScaler ADC 和NetScaler Gateway 13.1-59.19 之前的13.1 版本  
  
- NetScaler ADC和NetScaler Gateway 12.1和13.0 版本（易受攻击且已达生命周期）  
  
- NetScaler ADC 13.1-FIPS 和 NDcPP 13.1-37.236-FIPS 和NDcPP之前的版本  
  
  
  
思杰表示，“使用 NetScaler 实例的Secure Private Access 本地部署或 Secure Private Access 混合部署也受这些漏洞的影响。客户需要将这些 NetScaler 实例升级至 NetScaler 推荐版本。”  
  
思杰公司并未披露该漏洞如何被用于真实攻击中，但表示，“已观测到针对未修复设备的利用。”  
  
近日，思科还修复了位于 NetScaler ADC 中的另外一个严重漏洞CVE-2025-5777，CVSS评分9.3，被用于访问可疑设备。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[思杰修复 NetScaler ADC 和 Gateway 中的严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523373&idx=1&sn=046fdf8814e8311d4a31bd092804a2c2&scene=21#wechat_redirect)  
  
  
[Citrix悄悄修复相似度极高但严重性不及CitrixBleed的高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519419&idx=1&sn=3bb85759ff76414bd555bb55aa1b3c16&scene=21#wechat_redirect)  
  
  
[思杰ADM高危漏洞可导致管理员密码重置](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512458&idx=3&sn=b55867df7184e1bc35226d1d943cabe3&scene=21#wechat_redirect)  
  
  
[Citrix 分享Netscaler 密码喷射攻击的缓解措施](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521806&idx=1&sn=0678a9877c98e19004381988c56fc6c5&scene=21#wechat_redirect)  
  
  
[Citrix 督促 Mac 用户修复 Workspace App 中的提权漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519614&idx=1&sn=9e0519627dc928e416d3ba3de0a1941c&scene=21#wechat_redirect)  
  
  
[Citrix 提醒管理员手动缓解 PuTTY SSH 客户端漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519453&idx=1&sn=b108366a369534bc2bc55f5a5089d587&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/06/citrix-releases-emergency-patches-for.html  
  
  
  
题图：  
Pixabay Licen  
se  
  
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
  
