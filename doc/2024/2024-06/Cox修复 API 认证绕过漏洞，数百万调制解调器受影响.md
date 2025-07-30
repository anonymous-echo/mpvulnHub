#  Cox修复 API 认证绕过漏洞，数百万调制解调器受影响   
Sergiu Gatlan  代码卫士   2024-06-04 17:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Cox Communications 公司修复了一个授权绕过漏洞，可导致远程攻击者滥用被暴露的后台API，重置数百万个由 Cox 提供的调制解调器的设置并窃取客户的个人敏感信息。**  
  
Cox 是美国最大的私营宽带公司，通过光纤网络向美国30多个州的近700万个家庭和企业提供互联网、电视和电话服务。漏洞猎人 Sam Curry 发现了该漏洞，发现如成功利用该漏洞，可导致威胁行动者获得与互联网服务提供商技术支持一样的权限。  
  
攻击者已利用该访问权限利用可通过易受攻击 Cox API访问的数百万 Cox 设备，覆写配置设置并在设备上执行命令。例如，通过利用该认证绕过漏洞，恶意人员可利用被暴露的 API 通过客户的姓名、电话号码、电子邮件或账户等查找客户，之后窃取他们的个人可识别信息如MAC地址、邮件、电话号码和地址等。攻击者还能通过查询之前被盗的硬件 MAC 地址，收集联网设备的WiFi 密码和其它信息，随后执行越权命令、修改设备设置并获得对受害者账户的控制权限。  
  
Curry 表示，“这些漏洞展示了无需任何前提条件的完全外部的攻击者可执行命令并修改数百万调制解调器的设置、访问任何业务客户的个人可识别信息并获得和互联网服务提供商支持团队一样的权限。被暴露的API数量超过700个，很多都提供管理员功能（如查询调制解调器的联网设备）。每个API都遭受同样的问题，重复中继的HTTP请求可导致攻击者运行越权命令。”  
  
Cox 公司已在Curry 在3月3日报送的6小时内拿下被暴露的API调用并在第二天修复该漏洞。之后，Cox还调查了该攻击向量是否在报送前就已被暴露，结果表示并未发现此前遭滥用的证据。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Dell API 遭滥用 逾4900万客户记录被攻陷](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519473&idx=2&sn=73a7fe5d8c092b3ecb377410d2f6b9b3&chksm=ea94bd9bdde3348d56b3881455d7c0e9000e5905af5c3c91dcb9d20fc87de0812f7a771ea106&scene=21#wechat_redirect)  
  
  
[Ivanti 紧急修复 API 认证绕过0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517421&idx=1&sn=31756dd565b1bbd216e954def83c61dc&chksm=ea94b587dde33c91e83a737ae3eb0a14c48a427523b94dba12823b03eac1cecf97a890e21afa&scene=21#wechat_redirect)  
  
  
[Veeam：Backup Enterprise Manager 中存在严重的认证绕过漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519550&idx=2&sn=6b4de50a6ef98b37be097aae6daafa64&chksm=ea94bc54dde33542e89c9b2f5b6a2105c6c926040276e43b5afbb6b233fffe948a2df38e1334&scene=21#wechat_redirect)  
  
  
[速修复！Fortra GoAnywhere MFT 中存在严重的认证绕过漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518740&idx=1&sn=f97575a3c85c3e1d61c6ede1e31c0f1d&chksm=ea94bb7edde33268c42b5b9a74eb3ee30ceb5c34a906ff95500378175e985f1b8e0554fbcf3d&scene=21#wechat_redirect)  
  
  
[VMware 披露严重的VCD Appliance认证绕过漏洞，无补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518139&idx=2&sn=4951a6280d077d8cd04309f6629182e3&chksm=ea94b6d1dde33fc71b53f7879454b257d922f83689acde6d310a195b1857f38098ca7685fcca&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/cox-fixed-an-api-auth-bypass-exposing-millions-of-modems-to-attacks/  
  
  
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
  
