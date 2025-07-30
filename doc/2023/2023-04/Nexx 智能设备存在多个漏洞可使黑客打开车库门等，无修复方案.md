#  Nexx 智能设备存在多个漏洞可使黑客打开车库门等，无修复方案   
BILL TOULAS  代码卫士   2023-04-07 17:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**Nexx 公司的智能设备中存在多个漏洞，可被用于控制车库门、禁用家用报警器或智能插座等。这些被公开的漏洞共计五个，严重程度从中危到严重不一而足，该厂商尚未证实和修复这些漏洞。**  
  
  
  
其中最严重的问题是该厂商使用在固件中硬编码的全局凭据，且攻击者可通过 Nexx 的 API 从客户端通信可轻松获取这些凭据。该漏洞也可被用于识别 Nexx 用户，导致攻击者收集邮件地址、设备ID和名字等。该漏洞的编号为CVE-2023-1748，可用于打开任何受 Nexx 控制的车库门。  
  
今年1月4日，独立安全研究员 Sam Sabetan 发布了关于这些漏洞的 writeup，解释了攻击者如何可真实利用这些漏洞。据估算，至少有4万台 Nexx 设备与2万个账户相关联。鉴于该漏洞的严重性，CISA 也发布了相关告警信息。CISA 提醒 Nexx 产品用户称，攻击者能够访问敏感信息、执行 API 请求或劫持设备。  
  
  
**漏洞详情**  
  
  
Sebetan 发现的漏洞如下，影响运行版本 nxg200v-p3-4-1或更早版本的 Nexx Garage Door Controllers NXG-100B 和 NGX-200、运行 nxpg100cv4-0-0及更早版本的 Nexx Smart Plug NXPG-100W 以及运行 nxal100v-p1-9-1及更早版本的 Nexx Smart Alarm NXAL-100。  
  
- **CVE-2023-1748****：**使用上述设备中的硬编码凭据，任何人均可访问 MQ Telemetry Server 并远程控制任何客户的设备（CVSS评分 9.3）  
  
- **CVE-2023-1749****：**将API请求上的不当访问控制发送到合法的设备ID（CVSS评分 6.5）  
  
- **CVE-2023-1750****：**访问控制不当，可导致攻击者检索设备历史、信息和变更设置（CVSS评分7.1）  
  
- **CVE-2023-1751****：**输入验证不当，未能将授权标头中的令牌与设备ID关联（CVSS评分7.5）  
  
- **CVE-2023-1752****：**验证控制不当，可导致任意用户使用其MAC地址，注册已被注册的 Nexx 设备（CVSS 评分8.1）  
  
  
  
在这五个漏洞中，最严重的是CVE-2023-1748，是由 Nexx Cloud 通过安卓或 iOS Nexx Home 移动应用为所有新注册的设备设置了同一个全局密码导致的。该密码同时存在于 API 数据交换和设备交付的固件中，因此攻击者很轻松地可以获取并通过 MQTT 服务器将命令发送给设备，从而便于 Nexx 物联网设备的通信。  
  
尽管研究人员多次尝试联系 Nexx 公司，但均未收到回复。  
  
为缓解这些风险，建议Nexx 用户禁用设备的网络连接，部署防火墙保护并将其与任务关键网络隔离。如需远程访问或控制 Nexx 设备，则使用 VPN 连接，加密数据传输。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[研究人员发现Google 智能扬声器中的多个漏洞，获奖超10万美元](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515192&idx=2&sn=272bc0a3af1895e35d8757fc824d54e7&chksm=ea948d52dde3044428c3a85f3626292aa92baae3cad83b4c5ec41f5fe18285b316d2ca225fa6&scene=21#wechat_redirect)  
  
  
[Anker Eufy 智能设备系统易受严重的RCE漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512404&idx=2&sn=c658bb128dac22af8e2041f4d86d9c98&chksm=ea94803edde309286702f0b3b4638f0e87262ccd067fca6402a3f21d7cd880e36026452daa2e&scene=21#wechat_redirect)  
  
  
[联网智能设备安全态势季度报告（2021年第2季度）](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508375&idx=2&sn=f5baf37d1e44f891512723bf698862da&chksm=ea9490fddde319eb4ebcf81508e95c8b154da9b3f2214588db82323933ba73c46b7be917ac88&scene=21#wechat_redirect)  
  
  
[全球约30%的智能手机受高通新漏洞影响，打补丁状况不明](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247504006&idx=2&sn=5e3be0f6a913cde1548583ff6f77c3d2&chksm=ea94e1ecdde368faafea7d5c9e878dd3938c91343788cb8e7241a4c977e403ccdec05f49808e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/hackers-can-open-nexx-garage-doors-remotely-and-theres-no-fix/  
  
  
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
  
