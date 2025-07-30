#  思科： Webex 漏洞可导致凭据遭远程访问   
Sergiu Gatlan  代码卫士   2025-03-05 18:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**今天，思科提醒客户称，适用于 BroadWorks 的Webex 中存在一个漏洞，可导致未认证攻击者远程访问凭据。**  
  
适用于 BroadWorks 的Webex 将思科Webex的视频会议和协同特性与 BroadWorks 的统一通信平台集成。虽然思科尚未给该漏洞分配CVE编号，但在一份安全公告中提到已经推送配置变更修复该漏洞，并建议客户重启思科 Webex 应用以获得修复方案。  
  
思科解释称，“适用于BroadWorks 的Webex 45.2中存在一个低危漏洞，如为SIP通信配置了不安全的传输，则可导致未认证的远程攻击者访问数据和凭据。相关问题可导致认证用户访问客户端中的明文凭据和服务器日志。恶意人员可利用该漏洞和相关问题来访问数据和凭据并假冒用户。”  
  
该漏洞是由敏感信息暴露在SIP标头中引起的，仅影响在Windows 环境中运行的思科 BroadWorks（本地）和适用于 BroadWorks 的Webex（混合云/本地）实例。  
  
  
**缓解措施**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRBDyPpUD3WKJiatqGibMHcB6jLzUIvYnNHlnMPR84yvSej2K26HW2ibnZ6gMMZxWPVCfy8m9K8xkiaqQ/640?wx_fmt=gif&from=appmsg "")  
  
  
  
思科建议管理员为SIP通信配置安全传输，加密传输中的数据作为临时应变措施，直至环境中配备配置变更。思科还提到，“建议修改凭据，预防恶意人员已经获得凭据的情况。”  
  
该公司还提到，并未发现在野恶意利用该漏洞的迹象或分享更多漏洞信息的公开信息。  
  
本周一，CISA将2023年1月修复的思科漏洞CVE-2023-20118纳入必修清单。该漏洞可导致攻击者在RV016等路由器上执行任意命令。上个月也有其它报道称，未修复的思科IOS XE 网络设备已遭利用。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[德国政府会议信息遭泄露，思科修复 Webex 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519685&idx=3&sn=5ff2515ea003efe342365bfb3e9d8af7&scene=21#wechat_redirect)  
  
  
[即使静音，Webex仍在监控麦克风](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511433&idx=2&sn=b222aa11317b5ed8be8ed14722e20bc5&scene=21#wechat_redirect)  
  
  
[利用思科 Webex中的3个漏洞，以 ghost 用户身份参会](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247497644&idx=1&sn=1c4385263c64583912aece86dd8f4b3d&scene=21#wechat_redirect)  
  
  
[思科警告：“关键更新”钓鱼攻击窃取用户 Webex 凭证](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247492676&idx=2&sn=bcc4bfd9d617fe401cf8b38e80f3139f&scene=21#wechat_redirect)  
  
  
[思科为这个严重的 Webex 漏洞再次发布补丁](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488626&idx=1&sn=ad1c4927e6a1009c904e40fae9edffd9&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/cisco-warns-of-webex-for-broadworks-flaw-exposing-credentials/  
  
  
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
  
