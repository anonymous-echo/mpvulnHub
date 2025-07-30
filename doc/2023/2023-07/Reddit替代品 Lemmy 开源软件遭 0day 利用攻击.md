#  Reddit替代品 Lemmy 开源软件遭 0day 利用攻击   
Eduard Kovacs  代码卫士   2023-07-17 17:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**致力于替代 Reddit 的开源软件 Lemmy 遭0day漏洞利用攻击。**  
  
Lemmy 是一款开源软件，旨在运行自托管的新闻聚合和讨论论坛。虽然每个 Lemmy 实例由不同的个体或组织机构运行，但它们之间相互连接，可使一个实例的用户与其他服务器上的帖子进行交互。目前，该论文共有超过1100个实例以及近85万名用户。  
  
几天前，有人开始利用与自定义表情符渲染相关的XSS漏洞。攻击者利用该漏洞涂鸦某些流行实例上的页面，包括 Lemmy.world等，后者是最流行的实例，用户人数超过10万人。  
  
Lemmy.world 维护人员解释称，“几个规模更大的 Lemmy 实例的多个用户账户遭通过被盗认证 cookie 被攻陷。其中某些 cookie 属于管理员，这些管理员 cookie 用于涂鸦实例。只有在事件期间打开含有恶意内容的用户易受攻击。”他们还提到，“被盗 cookie 导致攻击者访问受影响用户的所有私密消息和电子邮件地址。”攻击者似乎使用受陷页面将用户重定向至令人讨厌的或令人震惊的内容。  
  
当攻击发生时，某些 Lemmy 实例被先行关闭。  
  
虽然该漏洞目前已修复，但仍然建议用户修改 JWT 机密信息。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[这个Python 0day 已存在15年，已影响超过35万个开源项目](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514063&idx=1&sn=af25c27ad54510e1a26e0be3ee3f9ae0&chksm=ea9486a5dde30fb370f1097da820fadd2dd27b86c0b224d0f788da0c94f8303e42379547afa8&scene=21#wechat_redirect)  
  
  
[开源电商平台 PrestaShop 0day被用于窃取在线商店的支付数据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513172&idx=2&sn=efb941fa694e08ecd1852c42d88e5e72&chksm=ea94853edde30c2880c50439a07c2422dee742fcf1fe0e72f90ed18a337cca789370f1e2b956&scene=21#wechat_redirect)  
  
  
[开源U-Boot 引导加载程序中存在两个未修复的严重0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512136&idx=1&sn=f1dff2c42ec635a5e317f36ae18cc7f3&chksm=ea948122dde30834305c643105f82ae611aa4a5aefda16ea90c19b366b76a46bf19dfeb70686&scene=21#wechat_redirect)  
  
  
[大企业都在用的开源 ForgeRock OpenAM 被曝预认证 RCE 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506349&idx=2&sn=c1cd744877e475629005b1d5af227712&chksm=ea94e8c7dde361d1f52c9723227cb5c5755da2dc97a1fc847d9f623ae484105ebd19f1011e0b&scene=21#wechat_redirect)  
  
  
[开源的杀毒软件 ClamAV 被曝 0day，exploit 已公开](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491497&idx=1&sn=19987f22124371bfbfb79951b7b1769e&chksm=ea972ec3dde0a7d5f69cfab9d8c584fdfeb4014863187a5be57a342c929c2eebd465899805b3&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/hackers-target-reddit-alternative-lemmy-via-zero-day-vulnerability/  
  
  
题图：Pixabay License  
  
  
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
  
