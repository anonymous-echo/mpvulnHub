#  SAP修复已遭利用的0day漏洞   
Bill Toulas  代码卫士   2025-04-27 10:12  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**SAP 公司紧急修复位于 NetWeaver 中的一个远程代码执行 (RCE) 0day 漏洞，它可用于劫持服务器。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTpOt1icw0pRNL9tiaHgGmwcSnusl6tVwwbgeKicqKoNdwfeweDHfuOibODsX207pwMhsH2p6iaGpArZeQ/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞的编号是CVE-2025-31324，CVSS评分10分，是一个位于SAP NetWeaver Visual Composer 的Metadata Uploader 组件中的未认证文件上传漏洞。该漏洞可导致攻击者在无需登录的情况下上传恶意可执行文件，从而可能导致远程代码执行和系统完全攻陷。  
  
尽管厂商的安全通告并未公开，但 ReliaQuest 在本周早些时候报道了关于 SAP NetWeaver Visual Composer '/developmentserver/metadatauploader' 端点上一个已遭利用的漏洞，它与CVE-2025-31324相符。ReliaQuest 报道称，通过 SAP NetWeaver 上的越权文件上传，多名客户受陷，攻击者将JSP webshell 上传到公开可访问的目录中。通过简单的向 JSP 文件发送的GET 请求就能够实现远程代码执行，导致攻击者从浏览器执行命令、进行文件管理操作（上传/下载）等。  
  
在利用后阶段，攻击者部署了红队工具 “Brute Ratel”、“Heaven’s Gate”安全绕过技术以及将通过 MSBuild 编译的代码秘密注入 dllhost.exe。ReliaQuest 在报告中提到，利用无需认证，受陷系统已完全修复，即这些系统曾遭 0day 利用。  
  
安全公司 watchTowr 也证实称发现了与CVE-2025-31324相关联的活跃利用。该公司的首席执行官 Benjamin Harris 表示，“未认证攻击者可滥用内置功能将任意文件上传到一个 SAP NetWeaver实例中，即实现完整的远程代码执行以及系统完全攻陷。watchTowr 发现这些威胁人员的活跃利用，他们利用这个漏洞将 web shell 后门释放到被暴露的系统并获得进一步的访问权限。该活跃的在野利用和广泛影响将非常有可能让我们看到多方的利用。”  
  
SAP公司回应称，CVE-2025-31324已在真实攻击中成功遭利用。该公司表示，并未发现SAP客户数据或系统受这些漏洞的影响，并在2025年4月8日发布了应变措施，补丁目前可用，建议客户立即应用补丁。网络安全公司 Onapsis 也发布报告称观测到漏洞遭活跃利用的迹象。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTpOt1icw0pRNL9tiaHgGmwcSQ5bquicNH9ef6sLKVNJBHLEOhm3WtXdN9aO28jpDJNwjsB9f4vjtR3w/640?wx_fmt=gif&from=appmsg "")  
  
**防御措施**  
  
  
该漏洞影响Visual Composer Framework 7.50，建议用户尽快应用最新补丁。  
  
该紧急安全更新是在SAP公司例行发布的“2025年4月”更新后发布的，因此如在本月初（2025年4月8日）已应用该更新，则仍然易受CVE-2025-31324漏洞的影响。此外，该应急更新还修复了其它两个严重漏洞CVE-2025-27429（SAP S/4 HANA中的代码注入）和CVE-2025-31330（SAP Landscape Transformation 中的代码注入）。  
  
建议无法立即应用更新的用户执行如下缓解措施：  
  
- 限制对 /developmentserver/metadatauploader 端点的访问权限。  
  
- 如未在使用 Visual Composer，则考虑完全将其关闭。  
  
- 将日志转发到 SIEM并扫描伺服小程序路径中的越权文件。  
  
  
  
ReliaQuest 建议执行深入的环境扫描，在应用缓解措施前定位和删除可疑文件。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[SAP AI Core中严重的 “SAPwned” 缺陷可引发供应链攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520194&idx=2&sn=7b4dbeae684f3e9a1f79148a5bacf221&scene=21#wechat_redirect)  
  
  
[SAP产品存在4个严重漏洞，其中1个位于ABAP内核中](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516897&idx=2&sn=f40a38c1290acb6b5b7f6553de58ab62&scene=21#wechat_redirect)  
  
  
[SAP 修复多个高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516461&idx=2&sn=1319c4b17cbfce2602f31c1375378a21&scene=21#wechat_redirect)  
  
  
[【Black Hat】SAP漏洞已遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513628&idx=1&sn=d47438e7ab536d8f38c3cc8dd64af9b0&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/sap-fixes-suspected-netweaver-zero-day-exploited-in-attacks/  
  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
