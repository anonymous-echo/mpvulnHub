#  微软证实称两个Exchange 0day 正遭在野利用   
Ravie Lakshmanan  代码卫士   2022-10-08 18:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
微软公开表示，正在调查影响Exchange Server 2013、2016和2019的两个0day遭在野利用事件。  
  
  
微软指出，“第一个漏洞是CVE-2022-41040，它是一个服务器端请求伪造漏洞。第二个漏洞CVE-2022-41082可导致攻击者在访问PowerShell的情况下实现远程代码执行后果。”  
  
微软还证实称，虽然已发现这些0day遭“有限的针对性攻击”，被用于获得对目标系统初始访问权限的情况，但强调称只有拥有对易受攻击Exchange Server的认证访问权限，攻击者才能实施成功利用。  
  
微软详述攻击指出，这两个缺陷被滥用于利用链中，该SSRF漏洞可导致认证攻击者远程触发任意代码执行。  
  
微软还进一步强调称，目前正在“加快”推出修复方案，同时督促Exchange本地用户在IIS Manager 中增加拦截规则，作为缓解潜在威胁的临时缓解措施。  
  
值得注意的是，Microsoft Exchange Online Customers 并不受影响。增加拦截规则的步骤如下：  
  
- 打开IIS Manager  
  
- 扩展 Default Web Site  
  
- 选择Autodiscover  
  
- 在特征视图中，点击URL Rewrite  
  
- 在右边Actions面板上，点击Add Rules  
  
- 选择Request Blocking，点击OK  
  
- 增加字符串".*autodiscover\.json.*\@.*Powershell.*"（不含引号）并点击OK  
  
- 扩展规则并选择Pattern为 ".*autodiscover\.json.*\@.*Powershell.*" 的规则，点击Conditions下面的Edit  
  
- 将条件输入从{URL} 更改为 {REQUEST_URI}  
  
  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[黑客在被黑的MS Exchange Server 上部署 IceApple 利用框架](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511792&idx=2&sn=9fc836e07a156357940dd2eb58198419&chksm=ea949f9adde3168ce5621cca35726a5e8edd36548400b016da2bcbd67093b7aba1cab58d6cc6&scene=21#wechat_redirect)  
  
  
[微软将本地版Exchange、SharePoint和Skype 纳入漏洞奖励计划](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511275&idx=4&sn=efe2927c135f8cf5c5c2663330e1a4f3&chksm=ea949d81dde31497c5ade51ddb1de4709626af7f0d773fe10c928c1eb7a230fd5b290868d5ff&scene=21#wechat_redirect)  
  
  
[微软 Exchange 服务器被滥用于内部邮件回复链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509371&idx=1&sn=7b2f20d019e3356cf298de0f2e20ebad&chksm=ea949411dde31d07f6e3b81997f5cee83ef78ea8825a971988034ad9e682a085d1627f603967&scene=21#wechat_redirect)  
  
  
[微软 Exchange Autodiscover 协议存bug，数十万域凭据可遭泄露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508034&idx=2&sn=d67ed074d76d721fa8a3a9fcabc0ba9e&chksm=ea949128dde3183e98cefda9510781207db9625f71b83890f1d8393fc60ed6f7a6147bd054ed&scene=21#wechat_redirect)  
  
  
[ProxyToken：微软 Exchange 服务器中的认证绕过新漏洞，可窃取用户邮件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507548&idx=1&sn=8bb0ef890eeea9a16bf623e46f1cc905&chksm=ea94ef36dde366207565bcd7bb7b772ef1ea6c1afda841a1bebf45d4a9544721381974569a9b&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2022/09/microsoft-confirms-2-new-exchange-zero.html  
  
  
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
