#  WiFi漏洞导致安卓和Linux设备易受攻击   
THN  代码卫士   2024-02-22 18:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**网络安全研究员在用于安卓、Linux 和 ChromeOS 设备中的开源 WiFi 软件中发现了两个认证绕过漏洞，可诱骗用户加入恶意版本的合法网络或在无需密码的情况下加入可信网络。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRoCrCAgkmRiaThl4MMrLrHkWc5uPK9MxEhgYBWua1x8gwkRwnO0YDTgfNSS6kc14t887MYrOeotIQ/640?wx_fmt=png&from=appmsg "")  
  
  
这两个漏洞是CVE-2024-52160和CVE-2023-52161，是对wpa_supplicant 和英特尔的 iNet Wireless Daemon (IWD) 分别进行安全评估时发现的。与 Mathy Vanhoef 协作研发的Top10VPN 表示这些漏洞“可诱骗受害者连接到恶意版本的可信网络并拦截其流量，并在无需密码的情况下加入安全网络。”  
  
具体而言，CVE-2023-52161可导致攻击者获得对受保护 WiFi 网络的未授权访问权限，导致现有用户和设备暴露到潜在攻击活动中如恶意软件感染、数据盗取和商务邮件攻陷 (BEC)。它影响 IWD 2.12及更低版本。  
  
CVE-2024-52160影响 wpa_supplicant 2.10及之前版本。这两个漏洞都是因为它是安卓设备用于处理无线网络登录请求的默认软件。话虽如此，该漏洞仅影响未能正确配置以验证认证服务器证书的 WiFi 客户端，而CVE-2023-52161则影响任何将 Linux 设备用作无线访问点 (WAP) 的网络。  
  
成功利用CVE-2023-52160的前提是攻击者拥有受害者此前连接的WiFi 网络的SSID，它还要求威胁行动者物理接近受害者。研究人员提到，“一个可能的场景是攻击者在企业大厦附近转悠，扫描网络，之后攻击离开办公室的员工。”  
  
Linux 的主要发行版本如 Debian、Red Hat、SUSE和 Ubuntu 等已发布相关安全公告。Wpa_supplicant 问题也在 ChromeOS 118和后续版本中修复，不过安卓版本的修复方案尚未出现。Top10VPN表示，“同时，安卓用户手动配置任何已保存企业网络的CA证书对于阻止攻击而言至关重要。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[联发科漏洞影响智能手机、平板、WiFi 等芯片集](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516937&idx=2&sn=65d504384b5ecc49b9c872f25971c1d9&chksm=ea94b263dde33b75aa7bd18b0397741b6641cd7b8e5a8e4ccfb85a349ff055e359e2aaccdaf6&scene=21#wechat_redirect)  
  
  
[CISA提醒：严重的 Ruckus 漏洞被用于感染 WiFi 接入点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516487&idx=2&sn=a0bd3a1e5ae0747b856ff42a50636fa1&chksm=ea94b02ddde3393b8a0a1ef90ddb1b3ee7f686b99ca6be0fbe36815c0c1d139cd46fda753f61&scene=21#wechat_redirect)  
  
  
[无线共存：利用蓝牙和 WiFi 性能特性实现芯片间提权](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509867&idx=2&sn=19471663d9505977efc3cef7e3a39044&chksm=ea949601dde31f17f54444101a87df6a48f743a459bdb122596fc52ff8d133aea1d207ff3488&scene=21#wechat_redirect)  
  
  
[Realtek WiFi SDK 被曝多个漏洞，影响供应链上至少65家厂商近百万台IoT设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507215&idx=1&sn=7c95fd8598c4f33e573e12e6f92c9808&chksm=ea94ec65dde36573649c4936289838a96ef4d81fe5a5b17b6c5f3603897fa056588850c946ae&scene=21#wechat_redirect)  
  
  
[Realtek WiFi 模块受严重漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505420&idx=2&sn=3bad3c929dfcd5812faed3393720d838&chksm=ea94e766dde36e70a8736027601336b5df286e4893b5cd484a1cd4df969185b924568ea445b3&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/02/new-wi-fi-vulnerabilities-expose.html  
  
  
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
  
