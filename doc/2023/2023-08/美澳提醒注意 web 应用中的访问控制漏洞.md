#  美澳提醒注意 web 应用中的访问控制漏洞   
Ionut Arghire  代码卫士   2023-08-01 17:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**澳大利亚网络安全中心 (ACSC) 、美国网络安全和基础设施安全局 (CISA)和美国国家安全局 (NSA) 联合发布新指南，提醒开发人员、厂商和组织机构注意 web 应用中的访问控制漏洞。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQiaCibdWDRxzISniagnzpXg7tnqJfStN3rtybNwJubSDzvSWb3UeRjwricz0icaCTl6QpemiatT4OhEe7g/640?wx_fmt=gif "")  
  
  
这些访问控制漏洞被称为不安全的直接对象引用 (IDOR) 问题，可使威胁人员通过包括合法用户标识符的 API 请求读取或篡改敏感数据。  
  
这些要求成功的原因是提交请求的用户的认证或授权未得到正确验证。指南指出，这些IDOR 漏洞可使用户以同样的权限或更高的权限访问本不应访问的数据，修改或删除数据或者访问本无权访问的函数。  
  
这些漏洞可通过修改 POST 请求主体中HTML 格式的字段数据、修改 URL 中的标识符或其它用户标识符的 cookie、或拦截和修改使用 web 代理的合法请求，触发这些漏洞。  
  
指南提到，“这些漏洞常被恶意人员在数据泄露事件中利用，因为这些漏洞很常见、难以在开发流程之外阻止且可遭大规模滥用。IDOR 漏洞导致数百万用户和客户的个人、金融和健康信息被攻陷。”  
  
为了阻止访问控制漏洞的流行以及保护敏感数据，建议 web 应用厂商、设计人员和开发人员执行安全设计和默认安全原则，确保访问或修改数据的每个请求都得到正确认证和授权。他们可使用自动化工具识别和修复 IDOR 漏洞，依赖间接引用地图阻止 URL 中的ID、姓名和密钥遭暴露并应验证应用中所包含的所有第三方库和框架。  
  
终端用户组织机构包括软件即服务组织机构，也应当审查所选 web  应用，遵循供应链风险管理最佳实践并及时应用可用补丁。  
  
建议部署本地软件、私有云或基础设施即服务的组织机构评估 web 应用中的可用认证和授权检查，定期扫描漏洞并执行渗透测试，保护面向互联网资产的安全。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[API 安全：访问控制破坏和注入攻击是2022年的最大企业威胁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513628&idx=2&sn=4d47a1f23df09272a5767c6beb5c0ce4&chksm=ea948776dde30e604eb1ac56dd4128f08a898f042760dec35552cdd21855dadfe5aa0e5b31d5&scene=21#wechat_redirect)  
  
  
[热门工业访问控制系统中存在8个严重0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512281&idx=1&sn=371c8c2da75df09506fe20a95f3dbe10&chksm=ea9481b3dde308a5fea3d23bd48bcbb36b3d924ac6d8fae85e882d49a0dc1803005630b8a316&scene=21#wechat_redirect)  
  
  
[【缺陷周话】第 21 期：数据库访问控制](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489185&idx=1&sn=8b10e9a6e12ba135675f97047fab7bf3&chksm=ea9727cbdde0aeddeb0dd721c78ca86c7019313ecef23d0303e373bce1bd7a09d8f2bf1b0474&scene=21#wechat_redirect)  
  
  
[Windows 10 “文件访问控制”反勒索功能可被绕过](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486445&idx=3&sn=01dcc758429a0a491109a2e0ac9c0d1a&chksm=ea973a87dde0b391b5da24fa0ee574c43bb841b6e06790a26648a605d9cc623b1e0e2745da1d&scene=21#wechat_redirect)  
  
  
[俄禁止网民使用访问被禁站点的工具 加紧对网络服务的控制](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485494&idx=5&sn=904c27cd80817eda897a334843e68636&chksm=ea97395cdde0b04aed1296d7dc4dabb6ca90d62a1991d26b23184e48a778cf39c60af97abfab&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/us-australia-issue-warning-over-access-control-vulnerabilities-in-web-applications/  
  
  
题图：Pexels License  
  
  
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
  
