#  NSO Group 被指利用零点击 iPhone 0day   
Sergiu Gatlan  代码卫士   2022-04-19 18:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J1TfC1KiaJk7cf6QAwOOQaqjLu1g8iatCpoGrC63KrUg28O1ia5ecf7VSTR9LjBicqbGyTavmo2Mzd4Eg/640?wx_fmt=png "")  
  
公民实验室的数字威胁研究员发现，一个新的零点击 iMessage exploit 被用于在加拿大政治家、记者和活动家的 iPhone 上安装 NSO Group 间谍软件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J1TfC1KiaJk7cf6QAwOOQaqjJr0R3PWpichEeruLhlJ1ibosp4nC0PFo5t2tLy8phVfyibica0j298bH8g/640?wx_fmt=png "")  
  
  
  
这个iOS 0day 缺陷被命名为 “HOMAGE”，影响 iOS 13.2（最新的iOS 稳定版是 15.4）之前的某些版本。它用于2017年至2020年间涉及 Pegasus 间谍软件攻击至少65名人员的活动中，它还利用了 Kismet iMessage exploit 和一个 WhatsApp 缺陷。  
  
在受害者中，公民实验室提到了欧洲议会的加泰罗尼亚成员，自2010年以来的每任加泰罗尼亚自治区主席，以及加泰罗尼亚立法人员、法官、记者以及民间团体组织机构的成员及其家属（注：加泰罗尼亚是西班牙的一个自治区）。  
  
公民实验室指出，“在加泰罗尼亚目标中，我们没看到对 iOS 13.1.3 之后版本设备使用 HOMAGE exploit，很可能该 exploit 已在 iOS 13.2 中修复。iOS 13.1.3之后版本和 iOS 13.5.1 之前版本的设备中并未见到任何0day、零点击exploit 针对加泰罗尼亚目标。”  
  
公民实验室向苹果公司提供了调查该 exploit 的取证工件，并表明并未发现使用 iOS 最新版本的苹果客户受 HOMAGE 攻击。  
  
公民实验室表示，“目前，公民实验室并未将这些黑客活动归因于某个政府，然而，一系列情境证据表明和西班牙政府内部一个或多个实体之间存在强关联。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX7CVwP3ChLicpEFMN4RzYLOyAUpxON3YANQDBL3bxBaPOKBz3p58HcCZR6BsV5zQpvdgLictCLNkLHw/640?wx_fmt=png "")  
  
**欧洲委员会、英国政府、芬兰外交官等也遭攻击**  
  
  
路透社报道称，NSO 间谍软件去年也被用于攻击欧洲委员会高级官员，包括欧洲司法专员。  
  
公民实验室总监 Ron Deibert 指出，公民实验室还向英国政府报告了英国官方网络内遭 Pegasus 监控软件感染的疑似实例。英国首相办公室的某名官员设备疑似受感染，其操纵者和阿联酋存在关联；与英国外交和联邦事务部相关的攻击活动与阿联酋、印度、塞浦路斯以及约旦之间存在关联。  
  
1月份，芬兰外交部指出，继美国国务院员工发现其 iPhone 遭入侵被安装 Pegasus后，芬兰外交官也遭感染。欧洲议会正在设立调查委员会，调查 NSO Pegasus及相关间谍软件违反欧盟法律的情况。  
  
Pegasus 是由以色列监控公司 NSO Group 开发的一款间谍软件工具，声称是向各国政府发放许可，用于“调查犯罪和恐怖活动”的监控软件。公民实验室解释称，“监控软件秘密渗透移动手机（和其它设备），可读取文本、监听通话、收集密码、追踪位置、访问目标设备的麦克风和摄像头并从应用中收割信息。加密通话和聊天也可被监控。感染结束后，这项技术甚至可以继续访问受害者的云账户。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2021中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505380&idx=1&sn=01d2f5af200abc6bb20411ee8f17b6b5&chksm=ea94e48edde36d98f20b66aecf9f359e49226b411872bcea527fcca0a5de018f407415313800&scene=21#wechat_redirect)  
  
  
[谷歌和GitHub 联手提出新方法，提振软件供应链安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511288&idx=1&sn=95ab4b2da101f01d766a05e120771c14&chksm=ea949d92dde314840f1ff2ae210cb525b81b8a51ea5041663de91c626b3fc40c09a8c586fb6b&scene=21#wechat_redirect)  
  
  
[GitLab 严重漏洞可用于接管用户账户](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511227&idx=3&sn=7d9cb5a28d01f069ecd0a9d12330dbd9&chksm=ea949dd1dde314c75fe3fe9eef38fc4eff8d0e0115e955adfca37a44f20407e89f1c5779291a&scene=21#wechat_redirect)  
  
  
[GitLab 严重漏洞可导致攻击者窃取runner 注册令牌](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510739&idx=3&sn=dfbf472143562f059fe28493b6edec7b&chksm=ea949bb9dde312afc2b4d13fadc6aad4d4d839a173d4ae2d1e7dee32ade2220066cd1e1b870a&scene=21#wechat_redirect)  
  
  
[逾3万台 GitLab 服务器仍未修复严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508920&idx=2&sn=c07b443b8b87dd6140264185685e1671&chksm=ea9492d2dde31bc45e0bef588ccc4142fdf96c0942df27b45cf2ff1a12d5f39f336139a39413&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/newly-found-zero-click-iphone-exploit-used-in-nso-spyware-attacks/  
  
  
题图：Pixabay License  
  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMQjfQ8ZhaOGYOwiaOkCe6UVnwG4PcibqI6sJ3rojqp5qaJa0wA2lxYb0VKwria7pHqS9rJwSPSykjMsA/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
