#  谷歌修复遭取证公司利用的两个 Pixel 0day漏洞   
Bill Toulas  代码卫士   2024-04-07 17:38  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**作者：**  
**Pierluigi Paganini**  
  
**编译：代码卫士**  
  
**谷歌修复了遭取证公司利用的两个 0day 漏洞。它们在没有PIN的情况下解锁手机并获得手机数据的访问权限****。**  
  
  
  
尽管Pixel 手机运行安卓系统，不过会从对所有安卓设备OEM发送的月度补丁中获得安全更新。这是因为谷歌直接控制它们的唯一硬件平台、唯一特性和能力。  
  
虽然安卓4月安全公告中并不包含任何严重问题，但 Pixel 设备的安全公告披露了对两个0day漏洞的利用，它们是CVE-2024-29745和CVE-2024-29748。  
  
谷歌提醒称，“有线索表明这两个漏洞可能已遭有限的针对性利用。”CVE-2024-29745是位于 Pixel 引导程序中的高危信息泄露漏洞，CVE-2024-29748是位于 Pixel 固件中的高危提权漏洞。  
  
从事隐私增强和安全的安卓分发平台 GrapheneOS称已发现取证公司正在活跃利用这些漏洞。这两个漏洞可导致企业解锁和访问具有物理访问权限的谷歌 Pixel 设备上的内存。  
  
几个月前，GrapheneOS发现并报送了这些漏洞，公开分享了一些信息，不过并未透露细节，避免在补丁发布前引发大规模的利用。GrapheneOS 平台指出，“CVE-2024-29745是位于用于支持解锁/删除/锁定 fastboot 固件中的漏洞。取证企业在Pixel和其它设备上将处于‘首次解锁后’状态的设备重启为 fastboot 模式，利用其中的漏洞并转储内存。”  
  
谷歌清空了启动fastboot模式时的内存，完成后仅启用 USB 连接，从而使攻击不可行。GrapheneOS 提到，CVE-2024-29748可导致本地攻击者避开由使用设备管理API的应用所发起的出厂重置，导致此类重置不安全。GrapheneOS 表示，谷歌对该漏洞的修复不完整，可能是不正确的，通过切断电源的方式仍然可能阻止刷新。目前该平台正在着手准备更加健壮的强制性 PIN/密码实现以及无需重启的更安全的 “紧急擦除” 操作。  
  
2024年4月的Pixel安全更新修复了24个漏洞，包括严重的提权漏洞CVE-2024-29740。用户可导航至设置＞安全和隐私＞系统和更新＞安全更新，并点击“安装”。完成更新需重启设备。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[谷歌修复 Pwn2Own 2024大赛发现的两个 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519170&idx=1&sn=31612ff9461ff59184a818b76f04c198&chksm=ea94baa8dde333be86a1b2054ea40407dfa5a45d469b948ac55085e5f64e7872f7e2007c90ad&scene=21#wechat_redirect)  
  
  
[谷歌修复2024年首个已遭利用的 Chrome 0day 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518705&idx=2&sn=1f6ee90c31f7b70d13390d0a735fe85f&chksm=ea94b89bdde3318da0dc7cd16e5e35198256a22c9c7f0dfa9132e438f6a90fa78fc85e7a63bf&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复今年第8个已遭利用的 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518459&idx=1&sn=16639910e34f9b7b38277934cf352d7e&chksm=ea94b991dde330870c970cec3c63ccbdb8634f61116a675b4e1ec25c90e9fc4ae7bd5fd02a04&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复2023年的第六个 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518238&idx=1&sn=5c52902fa6ddaf11504289e89f7e976f&chksm=ea94b974dde330620777f9cde78349529ef28ac4f9f9a9788b4aeded1ea2c3a19e9f56f90a98&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复已遭活跃利用的新 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517765&idx=1&sn=b7e9fb5dab86d46b0f3090c81402d31e&chksm=ea94b72fdde33e39a994bc9d7ccbb25cf3b14210ec657c34bea9464755eb08903ebc4e36eb7b&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/google-fixes-two-pixel-zero-day-flaws-exploited-by-forensics-firms/  
  
  
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
  
