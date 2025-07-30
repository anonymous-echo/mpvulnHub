#  Ivanti 紧急修复 API 认证绕过0day漏洞   
Jai Vijayan  代码卫士   2023-08-22 17:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**使用几乎任何版本的 Ivanti Sentry 安全网关产品的组织机构，应立即应用Ivanti 公司在今天发布的0day漏洞紧急补丁。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQESblthjLLPf9I8Tnbmrwia5Q9NUX3S8Jm5IISIXtXuBnaoOQdloyd7icjJiccfiboyrK7aymGZmKT9A/640?wx_fmt=png "")  
  
  
该漏洞的编号是CVE-2023-38035，位于管理员用于配置安全策略并使攻击者绕过认证控制的接口中。该漏洞影响所有受支持 Sentry 版本（9.18、9.17和9.16）。更老旧的Sentry不受支持版本和发布也易遭利用风险。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQESblthjLLPf9I8Tnbmrwial02jicib2yRZIdEGKEyP5xujUeP3bHJuztTBlfgAZo7xy5ticyYickfpuw/640?wx_fmt=gif "")  
  
**未认证的访问**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQESblthjLLPf9I8Tnbmrwia30hU0VRJA6nGRt7XzN6qbTGxqHrBzicyjUFRHz2zZxH7lGgXI4uJUJA/640?wx_fmt=png "")  
  
  
  
Ivanti 公司发布声明表示，“如遭利用，该漏洞可使未认证攻击者访问某些用于在管理员门户（端口8443）上配置 Ivanti Sentry 的敏感 API。”  
  
成功利用该漏洞的攻击者可更改网关配置、执行系统命令并在系统上写任意文件。要缓解风险，组织机构应当限制对管理员端口的访问仅限于内部管理网络而非互联网。  
  
该漏洞的CVSS评分为9.8，属于“严重”等级漏洞。不过Ivanti 公司提到，未暴露端口8443的组织机构几乎不受影响。至少有一家媒体报道称，Ivanti 披露该漏洞时，攻击者正在利用CVE-2023-38035，因此按照定义来说，该漏洞属于 0day 漏洞。  
  
Ivanti 公司并未就此事置评，并未提到是否已存在 exploit。该公司只是简单提到，发现仅有“少数客户”受该漏洞影响。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQESblthjLLPf9I8Tnbmrwial02jicib2yRZIdEGKEyP5xujUeP3bHJuztTBlfgAZo7xy5ticyYickfpuw/640?wx_fmt=gif "")  
  
**备受青睐的目标**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQESblthjLLPf9I8Tnbmrwia30hU0VRJA6nGRt7XzN6qbTGxqHrBzicyjUFRHz2zZxH7lGgXI4uJUJA/640?wx_fmt=png "")  
  
  
  
Ivanti Sentry 原名为 MobileIron Sentry，是 Ivanti 推出的统一端点管理产品之一。它是一种网关技术，可使组织机构管理、加密和保护移动设备和后端系统之间的流量。Ivanti 将Sentry 比作组织机构微软 Exchange Server 或其它 ActiveSync 服务器或后端系统如 Sharepoint 服务器的一个守门员。Sentry 可用作 Kerberos Key Distribution Center Proxy (KKDCP) 服务器。  
  
近年来很多公司都部署这类技术，确保远程员工可通过个人所有的和企业发放的移动设备安全地访问企业应用和设备。对这些技术的使用不断增长吸引了越来越多的安全研究员和攻击者。例如，就在上个月，攻击者在 Ivanti 端点管理器中找到并利用一个远程 API 访问漏洞，攻破了12家挪威政府机构的系统。该漏洞的编号是CVE-2023-35078，可使攻击者访问并窃取数据、更改设备的配置信息并增加管理员账户。本月早些时候，Ivanti 收到 ZDI 的报送后，披露了位于 Avalanche 移动管理技术中的另外一个漏洞 (CVE-2023-32560)。  
  
Ivanti 致谢安全厂商 Mnemonic 的研究员报送了该最新漏洞。Ivanti 提到，公司立即采取措施修复该漏洞并尽快为所有受支持版本发布可用的 RedHat Package Manager (RPM) 脚本。这些 RPM 脚本为每个版本自定义，组织机构应注意所适用的环境版本。该公司提到，“如果适用了错误的 RPM 脚本，可阻止漏洞修复或引发系统不稳定性。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2023中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517225&idx=1&sn=8154b433ae2be87ccbae15bc0fb09a00&chksm=ea94b543dde33c55c168c44e830d62b03e9b34ca072871d10156273a3f282cab7ccc42b9b430&scene=21#wechat_redirect)  
  
  
[奇安信发布《2023中国软件供应链安全分析报告》开源软件供应链的系统化安全治理需加速落地](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517165&idx=1&sn=c9c0c224c7eb021b526c03c079891642&chksm=ea94b287dde33b912cfba6f6ea911ca71a9002d5ca0a6a099ed818f2e235940920185d993340&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[挪威政府机构遭攻击，黑客利用的不止IT巨头 Ivanti的一个0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517282&idx=1&sn=92bc54d50120e90cdb14ffdc9575e7e5&chksm=ea94b508dde33c1eb06b110c0e5f8a197bfcb980488faddce9fee996ea1be88dc50821b49082&scene=21#wechat_redirect)  
  
  
[OWASP 发布2023年十大 API 安全风险清单](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516696&idx=1&sn=4b5b2574c1c80795d7c4ffa074942c66&chksm=ea94b372dde33a64a156b6dfd95ad01bc87df30eab4d81dcf8d5c5789f516a4ef9d348b743ac&scene=21#wechat_redirect)  
  
  
[研究员在微软 Azure API 管理服务中发现3个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516392&idx=3&sn=f563d9d06d17140943a9006f9816fecd&chksm=ea94b182dde33894747c1e2aa9ddbd52a923d8f1cc8ec0edd712caa946b58d97a9ac1bda8ecf&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.darkreading.com/attacks-breaches/ivanti-issues-fix-for-critical-vuln-in-its-sentry-gateway-technology  
  
  
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
  
