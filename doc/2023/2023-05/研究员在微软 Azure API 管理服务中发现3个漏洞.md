#  研究员在微软 Azure API 管理服务中发现3个漏洞   
Ravie Lakshmanan  代码卫士   2023-05-05 17:32  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**微软 Azure API 管理服务中存在三个新漏洞，可用于获得敏感信息或后端服务的访问权限。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQiaeicwYwMniaooQ9Ya2AGniapicIGZzn0tibjSbD0eXaybxZj8FTj6WcF6L14dnAVkIQmPmFBILO5HkCw/640?wx_fmt=png "")  
  
  
以色列安全公司 Ermetic 提到，在这三个漏洞中，两个是服务器端伪造 (SSRF) 漏洞，一个是位于 API 管理开发者门户中不受限的文件上传漏洞。  
  
研究员 Liv Matan 在报告中提到，“攻击者可利用这些SSRF 漏洞发送源自该服务 CORS Proxy 和托管代理本身的请求，访问内部 Azure 资产，拒绝服务并绕过 web 应用防火墙。攻击者可利用文件上传路径遍历漏洞，将恶意文件上传到 Azure 的托管内部工作负载中。”  
  
Azure API Management 是一个多云管理平台，可使组织机构将 API 暴露给外部和内部客户并赋能大量联网体验。在这两个SSRF漏洞中，其中一个是绕过微软部署的类似漏洞的修复方案。另外一个漏洞位于 API Management 代理功能中。  
  
利用这些 SSRF 漏洞可导致机密性和完整性缺失，导致攻击者读取内部 Azure 资源并执行越权代码。开发者门户中的路径遍历漏洞源自对所上传文件类型和路径的验证缺失。  
  
认证用户可利用该漏洞将恶意文件上传到开发者门户服务器，甚至在底层系统上执行任意代码。  
  
这三个漏洞均已修复。  
  
几周前，Orca 公司详述了位于微软 Azure 中的一个“设计缺陷”，它可被用于获得对存储账户的访问权限、在环境中横向移动甚至执行远程代码。更早之前，被称为 EmojiDeploy 的 Azure 漏洞可导致攻击者控制目标应用程序。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[谷歌不慎劫持BGP路由导致日本断网约1小时](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485478&idx=2&sn=3b5388e0f5981b1a7838003e73650a8d&chksm=ea97394cdde0b05a5e4fb2086bae12683b027cadf09e22603da6d6d8d88a9345a8d1e54fb2f3&scene=21#wechat_redirect)  
  
  
[五眼联盟发布关于智慧城市网络安全指南，含供应链风险管理](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516325&idx=2&sn=802bd0602e3c95e17a8956bbee298aa8&chksm=ea94b1cfdde338d9e18004ce2e506272bb0cde9a0a12909665bcc5b817543593173b3b9e5d4d&scene=21#wechat_redirect)  
  
  
[链中链？造成3CX 软件供应链事件的是另外一起供应链事件？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516298&idx=1&sn=e138d641346e77698d70abee3a29e62c&chksm=ea94b1e0dde338f6f767e54778211adb78e8788fc03bf10ec5b5ef9e6851b5efabf99041633b&scene=21#wechat_redirect)  
  
  
[Windows漏洞十年未修复，3CX供应链攻击影响全球60多万家企业](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516131&idx=1&sn=9ced8ade5f5884fcee054a1767486be1&chksm=ea948e89dde3079ff7147b94758c02675ebca5937a221a0e770238a109b77f798c296e082e35&scene=21#wechat_redirect)  
  
  
[黑客利用 3CX 木马版桌面 app 发动供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516096&idx=2&sn=e116004fbe089b4c4c2973cc6475b5ba&chksm=ea948eaadde307bcf9b88592627fc5ebcd68cade9ac4ccba9b66e8c0c2f74b16c35ef652bf36&scene=21#wechat_redirect)  
  
  
[供应链安全这件事，早就被朱元璋玩明白了](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515824&idx=1&sn=dab68a0c49b4d79f50b5c765c3bc2d89&chksm=ea948fdadde306cc2de185ca934b6c63d6e2e02e141f4612180b48e2c4ef56ec4da8bb826dd1&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/05/researchers-discover-3-vulnerabilities.html  
  
  
题图：Pixabay License  
  
  
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
  
