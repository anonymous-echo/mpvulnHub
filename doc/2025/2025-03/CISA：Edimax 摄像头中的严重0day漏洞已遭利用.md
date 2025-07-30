#  CISA：Edimax 摄像头中的严重0day漏洞已遭利用   
Eduard Kovacs  代码卫士   2025-03-10 17:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**CISA上周披露称，多个僵尸网络正在利用 Edimax IP摄像头中的 0day 漏洞。**  
  
  
  
  
  
  
  
CISA 发布安全公告提醒 Edimax IC-7100 IP摄像头用户称，该产品受一个严重的命令注入漏洞CVE-2025-1316影响，攻击者可通过特殊构造的请求实现远程代码执行，而该漏洞是因不正确地中和请求造成的。  
  
Edimax 是位于中国台湾省的一家网络解决方案提供商。CISA 提到该产品用于全球商业设施行业。CISA认为Edimax可能并未修复该漏洞，督促用户与厂商联系。IC-7100 网络摄像头被Edimax 列为“遗留产品”，也就是说它们可能已达生命周期且不受支持。  
  
虽然CISA并未明确说明该漏洞已遭在野利用，但却提到，“发现可疑恶意活动的组织机构应当按照已有的内部流程，将发现结果报送给CISA，以追踪并关联其它事件。”  
  
CISA表示该漏洞由Akamai公司发现，后者表示从2024年秋天起就发现该漏洞遭利用的迹象，它是在监控僵尸活动时发现的。该公司的研究员 Kyle Lefton 表示，该漏洞已遭多个基于Mirai 的僵尸网络的利用，而且它不过是这些僵尸网络所利用的其中一个漏洞。Lefton 表示CVE-2025-1316的利用虽然要求进行认证，但攻击者正在利用很多暴露到互联网的摄像头可通过已知默认凭据访问的事实实施利用。攻击者一旦获得对设备的访问权限，就会运行远程命令执行利用，并执行shell脚本，从远程服务器下载 Mirai 恶意软件payload。Edimax 公司并未就此置评。  
  
Edimax 公司在2024年10月收到通知，但并未回复CISA和Akamai的协同漏洞披露要求，不过它确实在去年告知Akamai表示并不会修复已达生命周期产品中的漏洞。Akamai 认为厂商应当更加严肃地对待该漏洞，因为它可能还影响受支持的产品。  
  
虽然CISA 在安全公告中提到CVE-2025-1316已遭利用但并未将其纳入必修清单（KEV）中。Akamai 公司将在未来几天内发布博客文章详述该漏洞。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[僵尸网络利用 GeoVision 0day 安装 Mirai 恶意软件](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521513&idx=2&sn=667b6f9c61b6f2d2077659cd4d4cdc70&scene=21#wechat_redirect)  
  
  
[未修复的 Apache Tomcat 服务器传播 Mirai 僵尸网络恶意软件](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517295&idx=1&sn=7f61402b12fbd46cb399a19ff93ca28e&scene=21#wechat_redirect)  
  
  
[Spring4Shell 漏洞已遭Mirai 僵尸网络利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511304&idx=2&sn=157f1ecf43e8268adf1d188b3bdab4db&scene=21#wechat_redirect)  
  
  
[Mirai 新变体利用严重漏洞攻击网络安全设备](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502508&idx=2&sn=b200aff65ee7010af420c66ce6ed061e&scene=21#wechat_redirect)  
  
  
[警惕！Mirai 新变体带着11个新利用攻击企业设备](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489462&idx=2&sn=5e37f9a866349fb70248e1ccd2fdf1ba&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/edimax-camera-zero-day-disclosed-by-cisa-exploited-by-botnets/  
  
  
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
  
