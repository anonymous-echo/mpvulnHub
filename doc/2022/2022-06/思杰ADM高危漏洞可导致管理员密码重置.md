#  思杰ADM高危漏洞可导致管理员密码重置   
John Leyden  代码卫士   2022-06-21 17:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMThIz9axluNe2c2NRzcN1SNcQcEB7Fk3ffsSY8tTpNG8ZFubaaAuMrX4EhhyjmdibaxxWLFfQFXnOg/640?wx_fmt=png "")  
  
思杰修复了位于应用交付管理 (ADM) 技术中的一个严重漏洞，可导致远程攻击者用于重置管理员密码。  
  
  
  
该漏洞是访问不当漏洞（CVE-2022-27511），可导致远程非认证用户通过拒绝服务 exploit 使系统崩溃，而且还可在下次重启时重置管理员凭据。  
  
上周，思杰发布安全公告称该漏洞可遭滥用，“在下次设备重启时重置管理员密码，导致拥有SSH 访问权限的攻击者在设备重启后连接默认的管理员凭据。”  
  
  
**获得访问权限**  
  
  
  
该问题的特别之处在于，它可将本是正常的系统损坏问题转变为更加严重的漏洞，而后者的严重性和未认证的远程代码执行缺陷的严重性相当。  
  
另外一个严重程度稍低的漏洞（CVE-2022-27512）可导致 ADM 许可证服务遭临时破坏。  
  
这些漏洞影响所有受支持的思杰 ADM 服务器和思杰 ADM 代理版本。它们都是由德国企业 Code White 的安全研究员发现的。  
  
思杰督促企业系统管理员升级至最新版本 Citrix ADM 13.1-21.53、Citrix ADM 13.0-85.19或后续版本。  
  
美国网络安全和基础设施安全局 (CISA)发布安全公告提醒称，“攻击者可利用这些漏洞控制受影响系统”，透露了该漏洞的严重程度。  
  
发现这两个漏洞的研究员拒绝置评，表示并无计划发布任何博客文章或技术分析文章。  
  
思科 ADM 为管理云上或本地的部署提供基于 web 的技术。尽管因瘦客户端计算而为人所知，但思杰提供了多种网络产品，为终端客户改进应用的速度和质量。该功能通过负载平衡和 web app 加速技术提供。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[思杰修复网络产品中的11个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247493959&idx=2&sn=96f8af18df7c83bc6579858bd626e035&chksm=ea94d82ddde3513b8b57413df61790da1d5ae2a43e40324f1989785e2e0f5136c3de54e572c0&scene=21#wechat_redirect)  
  
  
[思杰 ShareFile 被曝多个漏洞，可导致企业机密被盗](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247492950&idx=3&sn=2dd0c6986fb079c81d467581002ab9c3&chksm=ea94d43cdde35d2a000cf35c12ff6cae12010eaa71af59a56a827b0f1b7b731514c041746961&scene=21#wechat_redirect)  
  
  
[FIN7 正在转向密码重置和软件供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511248&idx=2&sn=3618e8bb492442ad7874823aeb44791c&chksm=ea949dbadde314acd88b1ad2e32bb8c2e70660bae3f14b907dfeee6565a4672dc5d34a88643c&scene=21#wechat_redirect)  
  
  
[用户应火速更新 Samba 服务器 修复密码重置和 DoS 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486660&idx=3&sn=3a4f8d852143947d05a0d9adf8c09197&chksm=ea973daedde0b4b8b9745edd4eb436b61552ec394d7507fbf8282588aac03797bfd1efc08329&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/critical-citrix-adm-vulnerability-creates-means-to-reset-admin-passwords  
  
  
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
