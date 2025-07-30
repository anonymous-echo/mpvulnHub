#  德国政府会议信息遭泄露，思科修复 Webex 漏洞   
Eduard Kovacs  代码卫士   2024-06-06 17:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**媒体报道称德国政府的 Webex 会议遭暴露，可能导致敌对势力获取高度敏感信息。本周二，思科发布安全公告。**  
  
德国媒体 Zeit Online 在5月4日发布文章指出，德国政府在实现思科 Webex 视频会议软件的过程中存在漏洞，可被用于获得内部会议以及高级官员会议室的链接。  
  
德国政府一直使用本地版 Webex 在本地服务器上存储数据并确保数据不会离开本国。然而，研究人员发现，进通过更改会议链接中的数字，敌对势力即可利用一个不安全的直接对象引用漏洞获取会议链接，暴露会议主题、时间以及参会人员信息，包括讨论军事活动的敏感会话等。另外，高层官员的个人会议室并未受密码保护，可导致敌对势力轻松访问并可能获得敏感信息。  
  
3月初，俄罗斯公开了德国军方在 Webex 平台上的一份音频记录，但目前尚不清楚这两起事件之间是否存在关联。为应对这些漏洞，德国政府拦截对被暴露会议室的访问权限并将 Webex 实例下线。  
  
思科在6月4日发布安全公告表示，已发布补丁但仍将持续关注越权活动。思科指出，“2024年5月早些时候，思科从Webex Meetings 中发现多个漏洞，我们认为这些漏洞用于针对性安全研究活动中，可越权访问托管在法兰克福数据中心的某些客户的Webex 部署中的会议信息和元数据。这些漏洞已修复并在2024年5月28日在全球范围内部署。”  
  
思科还指出，“思科已通知那些从可用日志上观测到的会议信息和元数据被访问的客户。这些漏洞修复后，思科尚未看到利用它们进一步获取会议数据或元数据的情况。”  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[国家黑客组织利用思科两个0day攻击政府网络](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519358&idx=1&sn=080e82a553f5a1d52ba96fc6f20d14c3&chksm=ea94bd14dde33402ba398352628a6ab2995cc8e1c950313b8a1b9fb5752d5c3d7a2f00098df9&scene=21#wechat_redirect)  
  
  
[思科修复IMC 高危根提权漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519311&idx=1&sn=d41f0d79f130254f124a7ea7404a3b12&chksm=ea94bd25dde33433a3f6fee230eea0ec03c4f96a3c2c63e2978e87fe79ae4a7a724a521d65e4&scene=21#wechat_redirect)  
  
  
[思科提醒注意Small Business路由器中的XSS漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519231&idx=2&sn=b7b32d73cbe2046719780c03304729ce&chksm=ea94ba95dde333834c93da6e263ab3af72ce14f2a171799c65802dab992336cd0c1a96492159&scene=21#wechat_redirect)  
  
  
[思科IOS 漏洞可导致未认证的远程DoS 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519204&idx=2&sn=6fc646b9575f6837ef0f55d569c11709&chksm=ea94ba8edde33398e567236352d40e34414aa12c9e4bd4d838bff320754289021c2fafcc02b8&scene=21#wechat_redirect)  
  
  
[思科修复 Data Center OS 中的多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518970&idx=1&sn=6962ea177a62fac9410b186624a2cd9a&chksm=ea94bb90dde332865540fed5893fa0fe3b2438bba6108c0ec68ea0e789667b29c274b976ec73&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/cisco-patches-webex-bugs-following-exposure-of-german-government-meetings/  
  
  
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
  
