#  热门 WordPress 插件 Ultimate Member 中存在严重漏洞   
Ionut Arghire  代码卫士   2024-02-29 19:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**安全厂商 Defiant 指出，WordPress 插件 Ultimate Member 中存在一个严重的SQL注入漏洞，其下载次数已达到20万次。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTX0IBdzN6IuWxX2dzYVNVeJiclPCUgQ77MacRqXcj5ExrKuLQ6d80v4Bh08UpG9eLNhv08jZOwn7Q/640?wx_fmt=gif&from=appmsg "")  
  
  
该漏洞的编号是CVE-2024-1071（CVSS评分9.8），影响运行 Ultimate Member WordPress 会员插件的网站，可被未认证攻击者在已有查询附加 SQL 查询并从数据库中提取信息。  
  
Defiant 公司提到，该漏洞存在的原因在于用户查询功能中的不安全实现，它可导致文本净化功能未能防御SQL注入攻击。研究人员还发现，该查询的机构仅允许攻击者采取基于时间的盲目方式，在使用SQL CASE 语句和睡眠命令的同时观察窃取信息请求的响应时间。Difant 公司在一份安全公告中提到，“这是在利用SQL注入漏洞时从数据库获取信息的复杂但常常会成功的方法。”然而，只有启用该插件“为用户元信息启用自定义表”的选项时该漏洞才会遭利用。研究人员提到，“这意味着并非所有运行该插件的用户都是内在易受攻击的，但无论如何，由于攻击者狡猾且可组合利用插件中的漏洞实现完全的站点接管，因此我们强烈建议立即更新。”  
  
该漏洞在1月30日报告，在2月19日推出的 Ultimate Member 2.8.3版本中修复。报送该漏洞的研究人员因此获得2063美元的奖励。建议用户尽快升级至已修复版本。Defiant 公司表示已经拦截了一次利用尝试。  
  
Ultimate Member 插件的下载量已超过20万次，它是用户资料和会员插件，可使 WordPress 站点管理员管理用户注册、登录、资料和角色。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[WordPress 插件 LiteSpeed 漏洞影响500万个站点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518947&idx=3&sn=a79e0235f3e78c2f4980247b4e0a365d&chksm=ea94bb89dde3329f127d8c01ddbfd59e454133a12f03962b70d34129434f08d38529852aa820&scene=21#wechat_redirect)  
  
  
[备份插件存在严重RCE漏洞，可导致WordPress网站遭接管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518349&idx=2&sn=da5a15622c08723ed8cacf81f9a2dd55&chksm=ea94b9e7dde330f1ebb50e99491cbc925e6e932730363f189179878a4dc2b3a4ccb480badb86&scene=21#wechat_redirect)  
  
  
[黑客利用WordPress 插件中的提权0day攻陷网站](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516908&idx=1&sn=3861a45ade1fc801daa3c767fef3f318&chksm=ea94b386dde33a90582ec8599b01780524bb88c9f1a2cd4cfd9874889611594313e5443e60b1&scene=21#wechat_redirect)  
  
  
[WordPress 紧急修复影响数百万网站 Jetpack 插件中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516649&idx=5&sn=3a673400f9a00b2b334fadfda1b0a8a9&chksm=ea94b083dde33995e9079edc64941b6bda561e4fbb1c4406e76ffcfb5423d723243494cbb5af&scene=21#wechat_redirect)  
  
  
[WordPress 热门插件中存在漏洞，200多万网站受影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516420&idx=2&sn=e419c137b012ee8e70e8514f7bf3a2e1&chksm=ea94b06edde339787fa928cc50927bb993d84cb037cf64c8f353c0b7afc9b6064576dddb5f44&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/critical-flaw-in-popular-ultimate-member-wordpress-plugin/  
  
  
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
  
