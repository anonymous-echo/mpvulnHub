#  思科不打算修复VPN路由器 RCE 0day   
Bill Toulas  代码卫士   2022-06-20 17:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSF3l35ZJV21sbRns4ljFBzZf8QoKMtN4qia91vx8Pd777cNT48w7hcTDVCM6ic3Rpe6ibXvk8DicHplg/640?wx_fmt=png "")  
  
思科建议已达生命周期的 Small Business RV 路由器所有人升级到更新机型，因为该路由器中存在一个远程代码执行0day 且思科不会修复。  
  
  
  
该漏洞的编号是CVE-2022-20825，CVSS评分为9.8。思科发布安全公告指出，该漏洞产生的原因在于对受影响设备上进站HTTP数据包的用户输入验证不充分。攻击者可向该 web 管理接口发送特殊构造的请求利用该漏洞，导致以root权限执行命令的后果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSF3l35ZJV21sbRns4ljFBzhWmrniaNycaTw80JcjNpXPLxeU461vuuh5j5kYhpC4PNHIETnjdjGSg/640?wx_fmt=png "")  
  
**影响和修复方案**  
  
  
该漏洞影响四款 Small Business RV 系列机型，具体为RV110W Wireless-N VPN Firewall、RV130 VPN Router、RV130W Wireless-N Multifunction VPN Router 和RV215W Wireless-N VPN Router。该漏洞仅影响启用了 WAN 连接上web远程管理接口的设备。虽然该远程管理特性在默认配置中并未启用，当通过 Shodan 引擎搜索可发现被暴露的设备。  
  
要判断是否启用了远程管理，管理员应登录该基于 web 的管理接口，导航至基本设置＞远程管理，并验证相关勾选框的状态。  
  
思科表示，由于这些设备不再受支持，因此将不会发布相关安全更新。另外，目前除了关闭 WAN 接口上的远程访问，尚不存在缓解措施。建议用户在迁移至提供支持的思科 Small Business RV132W、RV160或 RV160W 路由器之前应用配置变化。  
  
思科去年曾表示不会修复 UPnP 服务中的一个严重漏洞，并建议用户升级至更新版本。本周，思科修复了位于Secure Email 中的一个严重漏洞。该漏洞可导致攻击者绕过认证并登录到思科邮件网关的 web 管理接口。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[思科安全邮件设备现严重漏洞，认证机制可被绕过](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512362&idx=3&sn=70e454390ffa2bbcc942bc0ef7d5a286&chksm=ea948040dde309563ae79f6f57791819cbb113d3001d4dfc53dbf437979066bb00c594bb068d&scene=21#wechat_redirect)  
  
  
[思科修复严重的虚拟机逃逸漏洞，可使主机遭接管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511717&idx=2&sn=ac40bef80e111c4bb5d0ae860c5fe8f8&chksm=ea949fcfdde316d917f300ac371ad52391dc7ec6023680966dca6855444a1b3d569fcc34045c&scene=21#wechat_redirect)  
  
  
[思科修复 Expressway、TelePresence VCS 产品中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510769&idx=4&sn=48a5784077095eb4ef5b7a2ac2f3e421&chksm=ea949b9bdde3128d8976a76c8ce93b78e1c2ad7c91d6a1adf0cd2c99df745f13e75afd27a290&scene=21#wechat_redirect)  
  
  
[思科修复 SMB VPN 路由器中严重的代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247501122&idx=2&sn=1288d069487e7fe600ef17ac06f22898&chksm=ea94f428dde37d3e0319f43ab418cb78ff5133ba13de56ab60664e76188827709c7585e9af89&scene=21#wechat_redirect)  
  
  
[思科 AnyConnect 等企业 VPN 的认证和会话 cookie 存储方式被曝不安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489683&idx=1&sn=6a4240b37941f6ee4d6a08f15029816f&chksm=ea9729f9dde0a0ef1cf04ab2d0acda7dfb4368e35de5ab087f178d77e66ead4a39fd365e4132&scene=21#wechat_redirect)  
  
  
[VPN路由器存在 RCE 0day，思科不打算修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507288&idx=1&sn=35ea226a198d2e8b498fc0594f0c9e4c&chksm=ea94ec32dde365247ce79386abc905a55fa29ff709ced9085f116a97b44f37d5af3b6c853711&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/cisco-says-it-won-t-fix-zero-day-rce-in-end-of-life-vpn-routers/  
  
  
题图：  
Pixabay License  
‍  
  
  
  
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
