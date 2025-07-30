#  OT:Icefall：Wago 控制器中存在多个漏洞   
Ionut Arghire  代码卫士   2023-06-21 16:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
****  
**编译：代码卫士**  
  
**Forescout Technologies 公司详述了影响 Wago 和施耐德电气公司运营技术 (OT) 产品中的三个漏洞。**  
  
  
这些漏洞是 OT:Icefall 研究成果的一部分，该研究成果发现影响13家厂商100多款 OT 产品的61个漏洞。2022年6月，研究员首先发现56个漏洞，并在2022年11月分享了其它三个漏洞的详情，现在又新增了两个漏洞，同时分享了一个此前发现的但并未披露的漏洞信息。  
  
这两个新漏洞的编号是CVE-2023-1619和CVE-2023-1620，影响使用 Codesys v2 运行时的Wago 750 控制器，且可被认证攻击者用于触发拒绝服务条件。CVE-2023-1619 是因协议解析器的实现不良造成的，而CVE-2023-1620 是一个不充分的会话过期漏洞。认证攻击者可利用这两个漏洞，分别通过畸形数据包或登出后特定请求使设备崩溃。在这两种情况下，将设备返回到运行状态要求手动重启。  
  
Wago 750 自动化控制器用于商业设施、能源、制造和交通行业，支持多种协议，如 BACnet/IP、CANopen、DeviceNet Ethernet/IP、KNX、LonWorks、Modbus和PROFIBUS。  
  
Forescout 公司还分享了位于施耐德电气 ION 和 PowerLogic 产品线中的一个高危漏洞详情。虽然该漏洞属于第一批 OT:Icefall 漏洞，但应厂商要求并未公开披露。该漏洞的编号是CVE-2022-46680，影响功率表的 ION/TCP 协议实现。在每条消息中，该实现将用户ID和密码以明文形式传输，从而遭被动拦截流量的攻击者利用。  
  
Forescout 公司解释称，“获得ION或PowerLogic 凭据的攻击者可认证ION/TCP 工程接口以及SSH 和HTTP 接口，更改能源监控配置设置并可能修改固件。如所述凭据被用（复用）于其它应用，则它们如遭攻陷有利于横向移动。”  
  
这些设备不应从互联网访问，但Forescout 公司表示发现了被暴露在网络的2000至4000台可能是唯一的设备。多数已识别 Wago 控制器的HTTP协议遭暴露，施耐德电气的功率表暴露了 Telnet 协议。Wago 设备在欧洲（主要是德国、土耳其和法国）非常受欢迎，而ION 功率表在北美很流行。  
  
Forescout 总结为时一年的 OT:Icefall 研究成果时提到，已找到多个补丁不完整的实例，包括某些源自软件供应链组件的实例引入了新的漏洞。  
  
多数已发现漏洞（除了爱默生的 Ovation 分布式控制系统以外）都发布了安全公告，说明厂商对 OT:Icefall 的响应良好，尤其是与2021年Project Memoria 研究成果相比根式如此。后者从TCP/IP栈中发现了约100个漏洞，而仅有22.5%的受影响厂商发布了安全公告。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[多个严重漏洞可导致Wago PLC遭完全控制](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515851&idx=1&sn=7aafc9d34608057c1755ce4b0d26a630&chksm=ea948fa1dde306b7038337306579c85b3f678a5408a686056815961a98beb6ce83e933870a40&scene=21#wechat_redirect)  
  
  
[未修复漏洞可导致水泵控制器遭远程攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516114&idx=2&sn=430b1d4e9614f9b4e81d5de5e6b1ae9e&chksm=ea948eb8dde307aeaf7d488295dab582fa9cd7c306c29a64c23f69abb2dbed6ed5993532967a&scene=21#wechat_redirect)  
  
  
[合勤科技修复四个高危漏洞，影响AP、API控制器和防火墙设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512001&idx=3&sn=e25d8213ca24152e4fe49ee900f53295&chksm=ea949eabdde317bdbdb50c88bc48a6238c3d4eb1a57347b38b9cfba3db4a24295bf78c1d8951&scene=21#wechat_redirect)  
  
  
[BlueStacks 安卓模拟器被曝严重的 RCE 漏洞，可遭远程控制](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490293&idx=2&sn=19149187b96bbf61fe256691c830384b&chksm=ea972b9fdde0a28990bd4fe644c76024d6d32ca106b05d03c04ade75e0939e9ee2823c47e98c&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/oticefall-vulnerabilities-identified-in-wago-controllers/  
  
  
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
  
