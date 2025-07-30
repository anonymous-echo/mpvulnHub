#  MikroTik RouterOS 存在严重的提权漏洞   
THN  代码卫士   2023-07-27 17:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**MikroTik RouterOS 中存在一个严重的提权漏洞 (CVE-2023-30799)，可被远程恶意人员用于执行任意代码并完全控制易受攻击的设备。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTC64dm9d8xrebfJjKAGtg3jOfWicmLF9ia1P6ay6mnkWmbBMIdwK0HO9d7lgxjJ0UW60CcaYnic4GIQ/640?wx_fmt=gif "")  
  
  
CVE-2023-30799的CVSS评分为9.1，它导致约50万和90万 RouterOS 系统易分别遭通过 web 和/或 Winbox 接口的利用风险。  
  
安全研究员 Jacob Baines 指出，“CVE-2023-30799确实需要认证。实际上，该漏洞本身是一个简单的从管理员提升到超级管理员的提权漏洞，可导致任意函数遭访问呢。获取 RouterOS 系统的凭证要比想象得更加容易。”这是因为 Mikrotik RouterOS 操作系统并不提供任何关于密码暴力攻击的防护措施并提供已知的默认 “admin” 用户，而密码在2021年10月前是一个空字符串，RouterOS 6.49发布后，管理员被要求更新空密码。  
  
据称，CVE-2023-30799 最初由 Margin Research 在2022年6月发现并被命名为 FOISted，当时并未分配CVE编号。然而，该漏洞直到2022年10月13日才在 RouterOS 稳定版 6.49.7和在2023年7月9日发布的 RouterOS Long-term版本6.49.8中修复。  
  
研究人员提到，直接联系厂商并“发布攻击大量 MikroTik 硬件的新利用”后才发布了该 Longo-term 版本树的补丁。从所发布的 PoC 来看，攻击者可从 FOISted 中衍生新的基于 MIPS 架构的利用链并获得路由器的 root shell 权限。  
  
Baines 提到，“鉴于 RouterOS 一直以来都是 APT 组织的攻击目标，加上 FOISted 是在一年多前发布的，因此我们必须假设我们并非第一个发现该问题的团队。遗憾的是，检测几无可能。RouterOS web 和 Winbox 接口实现的自定义加密方案无法被 Snort 或 Suricata 解密和检测。一旦攻击者位于设备上，就很容易对 RouterOS UI 不可见。”  
  
Mikrotik 路由器中的漏洞被用于将设备纳入发动分布式拒绝服务僵尸网络如Mēris，并作为命令和控制代理，因此建议用户尽快更新至最新版本 6.49.8或7.x修复该漏洞。  
  
缓解措施包括从互联网删除 MikroTik 管理员接口、限制可登录管理员的IP地址、禁用 Winbox 和 web 接口，并将SSH配置为使用公/私钥并禁用密码。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Mikrotik 终于修复 Pwn2Own 大赛上的 RouterOS 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516569&idx=2&sn=c424da990afe03ec4a3f677d568e6a11&chksm=ea94b0f3dde339e5ceeb99709a2d5f43a0b8112918d915ab8e66ee70ecbaac23bf2dc9a95224&scene=21#wechat_redirect)  
  
[MikroTik 路由器被曝多个漏洞，可被用于创建后门](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491404&idx=2&sn=2f6cda89baa233b9caaf7284a14a49c5&chksm=ea972e26dde0a7302ec19e9210517e0711d2f52fb0b1d79dc1cd88b0f2027ed0d1e54620e84b&scene=21#wechat_redirect)  
  
  
[年满一岁的 DoS 漏洞仍导致某些 MikroTik 路由器易受攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489637&idx=2&sn=b178ba7b0910687c39948a2afb4130fc&chksm=ea97290fdde0a019f6142fa3332d0985c948be22f73e1fe6ec7559311fbc48f90baa3c828420&scene=21#wechat_redirect)  
  
  
[攻击新技术，让 MikroTik 路由器漏洞等级中危变严重](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488211&idx=2&sn=6e7e9cf1041c5031a5f78ea5fad1975e&chksm=ea9723b9dde0aaafea60c5bd9e564b1407a4c5edd6f79ca9c85515427535f1d5a3bd61f4ee6e&scene=21#wechat_redirect)  
  
  
[黑客利用全球MikroTik 路由器发动大规模密币劫持活动](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247487746&idx=1&sn=b35e70610616b9614c1402eaa54f2de6&chksm=ea972068dde0a97edad9aa1b4f16010beac520d8bcd5df031ce955d807e94b77bc33d2fad55b&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/07/critical-mikrotik-routeros.html  
  
  
题图：Pexels License  
  
  
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
  
