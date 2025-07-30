#  QNAP紧急修复已遭勒索团伙利用的0day   
Bill Toulas  代码卫士   2022-09-06 19:10  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
QNAP公司提醒客户称，始于上周六的正在进行的 DeadBolt勒索攻击利用的是位于 Photo Station 中的一个0day漏洞。QNAP公司已修复该漏洞但该勒索攻击仍在进行。  
  
  
  
QNAP公司发布安全公告指出，“QNAP® Systems, Inc. 检测到安全威胁 DEADBOLT 利用Photo Station 漏洞加密直接和互联网连接的 QNAP NAS设备。”这些攻击广泛传播，DeadBolt 向ID Randsomware 服务的提交数量在上周六和上周日激增。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQXqMhuNKR3T0ahnskbYvmwk0WT2swBaicia3I4c2daico0gTNt6Nsn1yNqK5argmFsTHCibvBItPt90w/640?wx_fmt=png "")  
  
  
**QNAP 发布0day 漏洞补丁**  
  
  
QNAP 公司在 DeadBolt 开始利用该0day漏洞12小时后发布了 Photo Station 安全更新，并督促NAS客户立即将Photo Station 更新至最新版本。  
  
如下安全更新修复了该0day：  
  
- QTS 5.0.1: Photo Station 6.1.2 及后续版本  
  
- QTS 5.0.0/4.5.x: Photo Station 6.0.22 及后续版本  
  
- QTS 4.3.6: Photo Station 5.7.18 及后续版本  
  
- QTS 4.3.3: Photo Station 5.4.15 及后续版本  
  
- QTS 4.2.6: Photo Station 5.2.14 及后续版本  
  
  
  
QNAP公司建议用户用 QuMagie 替代 Photo Station，前者是更安全的QNAP NAS 设备照片存储管理工具。QNAP公司指出，“我们强烈建议其QNAP NAS 不应直接连接到互联网。我们建议用户使用 QNAP 提供的myQNAPcloud Link 特性或者启用VPN服务。”  
  
应用安全更新将阻止 DeadBolt 勒索软件及其它威胁行动者利用该漏洞并加密设备。然而，NAS设备永远不应公开暴露到互联网，而应当部署防火墙保护。  
  
QNAP客户可通过安全公告了解这些安全更新的指南。最后，建议在所有NAS用户账户上使用强密码，并通过例行的快照阻止数据在攻击中丢失。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQXqMhuNKR3T0ahnskbYvmwk0WT2swBaicia3I4c2daico0gTNt6Nsn1yNqK5argmFsTHCibvBItPt90w/640?wx_fmt=png "")  
  
  
**DeadBolt：NAS 设备的勒索源头**  
  
  
DeadBolt 勒索团伙自2022年1月起就开始攻击 NAS设备，利用的是面向互联网的NAS设备上的一个0day漏洞。2022年5月和6月，该勒索团伙还在QNAP设备上执行更多攻击活动。2月初，DeadBolt 开始利用0day攻击ASUSTOR NAS 设备，他们试图以7.5个比特币的价格将该漏洞卖给该厂商。  
  
在多数攻击中，DeadBolt 都要求受影响用户支付1000多美元以交换起作用的解码器。不过，其它NAS勒索团伙勒索的更多。7月份，Checkmate勒索软件攻击QNAP NAS产品，要求受害者支付1.5万美元。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[严重的PHP缺陷可导致QNAP NAS 设备遭RCE攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512551&idx=2&sn=62ca391c055ea2839fe4178afcd48f4b&chksm=ea94808ddde3099be6ec5044d096c7921e4abb430485bfbd3eb207e3fa39af16c7a0ca6a766b&scene=21#wechat_redirect)  
  
  
[QNAP 延长对某些不受支持NAS设备的关键更新](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510517&idx=2&sn=b46c734e2964ef630b8aca33967cd650&chksm=ea94989fdde31189597f79fdc85b321aa74bc47938baef54edeacea6b41bffcbfe2350815322&scene=21#wechat_redirect)  
  
  
[QNAP 修复 NAS 备份应用中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506155&idx=2&sn=8f7fdfda2b503275dc60dcca755a4573&chksm=ea94e981dde3609733bf222b2eb637a96066b4c40b0855468408401edfa03146e0851ef4c055&scene=21#wechat_redirect)  
  
  
[QNAP 提醒客户注意 eCh0raix 勒索攻击和 Room Server 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247504237&idx=3&sn=43c42792dfa40b987073b70e8a953e36&chksm=ea94e007dde36911528c383eb4c89b792f74533a57b421f44886b84e2a9c74ddc10199682202&scene=21#wechat_redirect)  
  
  
[RCE 0day影响数万台QNAP SOHO NAS 设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247503218&idx=3&sn=80d4f2d0b1484dad642055b80ef8ed3e&chksm=ea94fc18dde3750ecc5a0d6bbf95783b38303c85b8a84726bbddf683bd7a86e732a25c914f28&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/qnap-patches-zero-day-used-in-new-deadbolt-ransomware-attacks/  
  
  
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
