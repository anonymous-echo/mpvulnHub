#  亚马逊悄悄修复安卓相册 app 中的高危漏洞   
Jonathan Greig  代码卫士   2022-06-30 18:21  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQ14gANfpzIJKovICjicY8CHcLrp6fhEAC73OFcp8ibm4E3Y1ZVUgf3QuCia6fcYt1rsFPxnomIlbO7A/640?wx_fmt=png "")  
  
亚马逊披露称，收到研究员的漏洞报告后，在去年12月修复了 Amazon Photos Android app 中的一个高危漏洞。  
  
  
  
网络安全公司 Checkmarx 的研究员表示从该 app 中发现了一个漏洞，可导致攻击者窃取用户的亚马逊访问令牌。该令牌用于认证多个亚马逊API。其中很多 API 中含有个人数据如姓名、邮件、地址等。其中一些API 如 Amazon Drive API 可导致黑客完全访问个人文件。  
  
在12月18日发布漏洞补丁前，亚马逊 Photos 安卓 app的下载量超过5000万次。  
  
亚马逊的一名发言人指出，公司“未发现因该问题暴露客户敏感信息的证据”，并表示，“感谢独立安全研究员向我们提出潜在安全问题。我们收到报告后不久发布修复方案。目前并未有证据表明敏感的客户信息因此而被暴露。”  
  
Checkmarx 公司的安全研究副总裁 Erez Yalon 指出，团队发现该 app 多个不同组件的多个问题，并发现安装了正确的恶意app 后，安卓用户的亚马逊访问令牌“可被盗，导致用户易受勒索攻击或更严重的风险。”  
  
他解释称，“问题是由com.amazon.gallery.thor.app.activity.ThorViewActivity 组件的配置不当造成的，该组件被导出在该app的表示文件中，从而使外部应用进行访问。无论该活动何时启动，都会触发一个HTTP请求，带有含客户访问令牌的标头。更重要的是，研究人员发现他们能够控制接收该请求的服务器。该活动由应用使用的意图过滤器声明，判断该请求的目标中包含该访问令牌。”  
  
恶意应用可“发送能够启动易受攻击活动的意图，促使请求被发送至由攻击者控制的服务器中”。  
  
研究人员表示，任何人只要获得访问令牌，就能够修改文件同时擦除用户历史，从而使原始内容无法从历史中恢复。研究人员发现了攻击者可删除他人 Amazon Drive 中文件的其它方式。报告指出，理论上勒索团伙有多种方式利用该缺陷，“恶意人员仅需要读取、加密并重写客户文件，同时擦除历史。另外，本文中所强调的 APIs 仅仅是整个亚马逊生态系统的一个子集，因此具有同样令牌的攻击者很可能可以访问其它Amazon APIs。”  
  
Checkmarx 公司表示已在2021年11月7日，将问题告知亚马逊漏洞研究计划。第二天，亚马逊证实该报告并认为属于“高危问题”。  
  
12月18日，亚马逊宣布称该问题“已修复”且表示“在生产中部署了”修复方案。研究人员表示，“我们知道软件世界中并不存在完全安全的情况。但在全球安全实践方面处于领先地位的亚马逊软件中发现这种漏洞，意味着它可以发生在任何软件公司中。”  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[亚马逊的 Log4j 热补丁易受提权漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511504&idx=3&sn=db5e57652474eb1850d3b2b14ac08b7d&chksm=ea949cbadde315ac5a2e1ec42b1f22f41a109103847e4fd1d2ea90423d2291aaec360750ffa4&scene=21#wechat_redirect)  
  
  
[亚马逊RDS使用的第三方扩展有漏洞，可导致内部凭据遭泄露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511336&idx=3&sn=93a217a5bfd2056aec0ae7633e675688&chksm=ea949c42dde3155465e90611111b59f4c623f0d79f5c00a2e3a3b2664c89e8888ebbada4a4ef&scene=21#wechat_redirect)  
  
  
[【BlackHat】亚马逊和谷歌修复DNS即平台中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506794&idx=2&sn=77fc6e3bbe9943691550b0decc97b793&chksm=ea94ea00dde3631635fc28b9a9c4f3ce7599beaf8c536179175d9a5e595184ba59b4ee5fb0ae&scene=21#wechat_redirect)  
  
  
[依赖混淆 exploit 已被滥用于攻击亚马逊等多家大厂](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247501946&idx=2&sn=225e6c564f5f6957cd3c58ebccd0de5f&chksm=ea94f910dde3700643f0f0c3841e2db050dcdc7ad21103e54f1bd01f21cad834d44cec9937ad&scene=21#wechat_redirect)  
  
  
[亚马逊 AWS 大宕机，大量互联网服务无法使用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247498053&idx=2&sn=35df3e6b3b9ecdba910696198399bb62&chksm=ea94c82fdde34139329f7b839ff66346a9d9cacf299ef3c8653a7a10db048b6a25bf75add112&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://therecord.media/amazon-quietly-patches-high-severity-android-photos-app-vulnerability/  
  
  
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
